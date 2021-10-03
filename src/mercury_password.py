"""
Implements password search
"""

import argparse
import logging

from mercury.mercury import MercuryDriver, MercuryADDR

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO
)


def progressbar(position, total, end=""):
    """
    Draws a progress bar in CLI
    """
    max_v = total - 1
    pb_len = 50
    pb_curpos = int(position / max_v * pb_len)
    pb_percent = int(position / max_v * 100)
    print(
        f'\r[ {"#" *  pb_curpos}{"-" * (pb_len-pb_curpos)} ] {pb_percent}%\t{end}',
        end="",
        flush=True,
    )


def parse_args():
    """
    Parse CLI args

    return: ArgumentParser
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "serial", type=str, nargs="?", required=True, help="Serial port. e.g. USB4"
    )
    parser.add_argument(
        "address", type=int, nargs="?", default=MercuryADDR.UNIVERSAL, help="address"
    )
    args = parser.parse_args()
    return args


def main():
    """
    Opens a channel to a counter, and tries all possible passwords
    """
    args = parse_args()
    com = args.serial
    address = args.address

    logging.info(f"Starting for serial {com}, address {address}")

    counter = MercuryDriver(com, address)
    counter.test_connection()
    counter.logout()

    passwords = range(0, 1000000)
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
