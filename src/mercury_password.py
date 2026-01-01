"""Implements password search."""

import argparse
import logging

from mercury.mercury import MercuryADDR, MercuryDriver


def progressbar(position, total, end="") -> None:
    """Draws a progress bar in CLI."""
    max_v = total - 1
    pb_len = 50
    int(position / max_v * pb_len)
    int(position / max_v * 100)


def configure_logging(level=logging.INFO) -> None:
    logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=level)


def parse_args():
    """Parse CLI args.

    return: ArgumentParser
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("serial", type=str, nargs="?", help="Serial port. e.g. USB4")
    parser.add_argument(
        "address", type=int, nargs="?", default=MercuryADDR.UNIVERSAL, help="address",
    )
    parser.add_argument(
        "psw_range_start",
        metavar="psw-range-start",
        type=int,
        nargs="?",
        default=0,
        help="password range start",
    )
    parser.add_argument(
        "psw_range_end",
        metavar="psw-range-start",
        type=int,
        nargs="?",
        default=1000000,
        help="password range end",
    )
    parser.add_argument("--debug", action="store_true", help="enable detailed logging")
    parser.add_argument(
        "--serial-echo-mode",
        type=str,
        nargs="?",
        default="auto",
        const="auto",
        choices=["enabled", "disabled", "auto"],
        help="Serial port echo mode",
    )
    return parser.parse_args()


def main() -> None:
    """Opens a channel to a counter, and tries all possible passwords."""
    args = parse_args()
    com = args.serial
    address = args.address
    echo_mode = args.serial_echo_mode
    configure_logging((logging.INFO, logging.DEBUG)[args.debug])

    logging.info(f"Starting for serial {com} ({echo_mode}), address {address}")
    if com is None:
        logging.fatal("You MUST specify a COM port.")
        return

    counter = MercuryDriver(com=com, addr=address, echo_mode=echo_mode)
    counter.test_connection()
    counter.logout()

    passwords = range(args.psw_range_start, args.psw_range_end)
    total = len(passwords)
    logging.info("Trying %i passwords:", total)
    progressbar(0, total, "")
    for pos, psw in enumerate(passwords):
        psw_s = str(psw).zfill(6)
        progressbar(pos, total, psw_s)
        if counter.login(psw=psw):
            logging.info("Login successful with %s", psw_s)
            break
    counter.logout()
    logging.info("Done.")


if __name__ == "__main__":
    main()
