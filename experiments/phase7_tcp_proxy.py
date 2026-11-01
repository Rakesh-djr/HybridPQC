#!/usr/bin/env python3
"""TCP impairment proxy for Phase 7 handshake experiments.

RTT is implemented as half the configured delay in each forwarding direction.
Bandwidth is a per-direction byte pacing limit. A configured loss event holds
an intact byte chunk for a recovery interval; it approximates a retransmission
stall but does NOT drop IP packets or emulate TCP congestion control.
"""

import argparse
import asyncio
import csv
import os
import random
import time
from datetime import datetime, timezone


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=5555)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=5556)
    parser.add_argument("--rtt-ms", type=float, default=0.0)
    parser.add_argument("--bandwidth-kbps", type=float, default=0.0,
                        help="per direction; 0 disables rate limiting")
    parser.add_argument("--loss-event-percent", type=float, default=0.0,
                        help="chance of delaying each forwarded chunk")
    parser.add_argument("--loss-recovery-ms", type=float, default=200.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--log-csv", default="")
    args = parser.parse_args()
    if args.rtt_ms < 0 or args.bandwidth_kbps < 0 or args.loss_recovery_ms < 0:
        parser.error("delay, bandwidth, and recovery values must be nonnegative")
    if not 0 <= args.loss_event_percent <= 100:
        parser.error("loss-event-percent must be between 0 and 100")
    return args


async def relay(reader, writer, direction, stats, args, rng):
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return

            if args.rtt_ms:
                await asyncio.sleep(args.rtt_ms / 2000.0)

            if args.loss_event_percent and rng.random() * 100.0 < args.loss_event_percent:
                stats["loss_holds"] += 1
                await asyncio.sleep(args.loss_recovery_ms / 1000.0)

            if args.bandwidth_kbps:
                delay = len(data) * 8.0 / (args.bandwidth_kbps * 1000.0)
                if delay:
                    await asyncio.sleep(delay)

            writer.write(data)
            await writer.drain()
            stats[direction] += len(data)
    except (ConnectionError, asyncio.CancelledError):
        return


async def handle_client(client_reader, client_writer, args, rng, connection_id):
    started = time.perf_counter()
    stats = {"client_to_server_bytes": 0, "server_to_client_bytes": 0,
             "loss_holds": 0}
    server_writer = None
    try:
        server_reader, server_writer = await asyncio.open_connection(
            args.target_host, args.target_port)
        print(f"connection {connection_id}: forwarding to "
              f"{args.target_host}:{args.target_port}", flush=True)
        await asyncio.gather(
            relay(client_reader, server_writer, "client_to_server_bytes",
                  stats, args, rng),
            relay(server_reader, client_writer, "server_to_client_bytes",
                  stats, args, rng),
        )
    except (ConnectionError, OSError) as exc:
        print(f"connection {connection_id}: proxy error: {exc}", flush=True)
    finally:
        for writer in (client_writer, server_writer):
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass

        duration_ms = (time.perf_counter() - started) * 1000.0
        row = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "connection_id": connection_id,
            "rtt_ms": args.rtt_ms,
            "bandwidth_kbps_per_direction": args.bandwidth_kbps,
            "loss_event_percent": args.loss_event_percent,
            "loss_recovery_ms": args.loss_recovery_ms,
            "loss_holds": stats["loss_holds"],
            "client_to_server_bytes": stats["client_to_server_bytes"],
            "server_to_client_bytes": stats["server_to_client_bytes"],
            "duration_ms": round(duration_ms, 3),
        }
        print(f"connection {connection_id}: {row}", flush=True)
        if args.log_csv:
            exists = os.path.exists(args.log_csv)
            with open(args.log_csv, "a", newline="", encoding="utf-8") as output:
                writer = csv.DictWriter(output, fieldnames=row.keys())
                if not exists:
                    writer.writeheader()
                writer.writerow(row)


async def run(args):
    rng = random.Random(args.seed)
    connection_id = 0

    async def accept(reader, writer):
        nonlocal connection_id
        connection_id += 1
        await handle_client(reader, writer, args, rng, connection_id)

    server = await asyncio.start_server(accept, args.listen_host, args.listen_port)
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Phase 7 proxy listening on {addresses}; RTT={args.rtt_ms} ms, "
          f"bandwidth={args.bandwidth_kbps} kbps/direction, "
          f"loss-event holds={args.loss_event_percent}%", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        print("Phase 7 proxy stopped.")
