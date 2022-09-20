#!/usr/bin/env python3
"""Script to query a MISP galaxy and resolve synonyms."""
import argparse
import os
import sys

from galaxy_parser import galaxy
from galaxy_parser import discerner
from galaxy_parser import exceptions

from typing import List


TMP_DIR = "/tmp/"


def get_discerners(
    galaxy_manager: galaxy.BaseGalaxyManagerSubType,
    galaxy_names: List[str],
    source: str = None
) -> List[discerner.BaseDiscernerSubType]:
    """Return a list of dynamically created discerners."""
    discerners = []
    for galaxy_name in galaxy_names:
        new_type = discerner.BaseDiscerner.create_class(galaxy_name, source or "custom")
        discerners.append(new_type(galaxy_manager))
    return discerners


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q",
        "--query",
        dest="query",
        type=str,
        required=True,
        help="query",
    )
    parser.add_argument(
        "-g",
        "--galaxy-list",
        dest="galaxy_list",
        nargs='+',
        default=["mitre-intrusion-set", "mitre-malware", "mitre-tool"],
        help="list of galaxy clusters to query",
    )
    parser.add_argument(
        "-f",
        "--force-download",
        dest="force_download",
        default=False,
        action="store_true",
        help="whether to force download",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="whether to be verbose",
    )
    args = parser.parse_args()

    # Make sure we can write to a temporary directory
    if os.access(TMP_DIR, os.W_OK):
        cache_directory = TMP_DIR
    else:
        cache_directory = "./"

    # Create galaxy manager and discerners
    galaxy_manager = galaxy.GalaxyManagerOnDemand(
        cache_directory=cache_directory,
        galaxy_names=args.galaxy_list,
        verbose=True,
        force=args.force_download,
    )
    discerners = get_discerners(galaxy_manager, args.galaxy_list)

    # Process
    labels = []
    for d in discerners:
        try:
            discernment = d.discern(args.query)
            labels.append(discernment.get_tag())
        except exceptions.FailedDiscernment:
            pass
    print(f"Mapping '{args.query}' to: ", labels)

    return 0


if __name__ == "__main__":
    sys.exit(main())
