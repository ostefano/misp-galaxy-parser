#!/usr/bin/env python3
"""Script to replace stale cluster tags."""
import argparse
import configparser
import logging
import pymisp
import sys
import warnings

from typing import List
from typing import Dict
from typing import Set
from typing import Union
from typing import Iterable

from galaxy_parser import galaxy


warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Configure the loggers
logging.basicConfig(
    format="%(asctime)s %(pathname)s %(lineno)d %(levelname)-8s %(message)s",
    level=logging.INFO,
)

# Galaxies whose clusters have a suffix-based identity
SUFFIX_BASED_GALAXIES = frozenset([
    "mitre-attack-pattern",  # MITRE techniques can be renamed, but the technique id remains
])


def is_tag_stale__by_suffix(actual_tag: str, tag: str) -> bool:
    if actual_tag == tag:
        return False
    return actual_tag.split(" - ")[-1] == tag.split(" - ")[-1]


def is_tag_stale__by_synonym(actual_tag: str, tag: str, synonyms: Dict[str, Set[str]]) -> bool:
    if actual_tag == tag:
        return False
    return actual_tag in synonyms[tag]


def get_tag(galaxy_prefix: str, value: str) -> str:
    return f"{galaxy_prefix}=\"{value}\""


def get_tag_synonyms(galaxy_values: Iterable[Dict], galaxy_prefix: str) -> Dict[str, Set[str]]:
    synonyms = {}
    for entry in galaxy_values:
        synonyms[get_tag(galaxy_prefix, entry["value"])] = {
            get_tag(galaxy_prefix, x) for x in entry.get("meta", {}).get("synonyms", [])
        }
    return synonyms


def get_galaxy_names_from_tag_names(tag_names: Iterable[str]) -> List[str]:
    tag_galaxy_names = set([])
    for tag_name in tag_names:
        try:
            tag_category, tag_galaxy = tag_name.split("=")[0].split(":")
            if tag_category == "misp-galaxy":
                tag_galaxy_names.add(tag_galaxy)
        except (IndexError, ValueError):
            continue
    return sorted(tag_galaxy_names)


def search_and_replace_tag(
    misp: pymisp.PyMISP,
    entity: Union[pymisp.MISPAttribute, pymisp.MISPEvent],
    old_tag: str,
    new_tag: str,
) -> None:
    tag_by_name = {x.name: x for x in entity.tags}
    if old_tag not in tag_by_name:
        return
    if new_tag not in tag_by_name:
        results = misp.search_tags(new_tag, pythonify=True)
        if results:
            tag_object = results[0]
        else:
            tag_object = pymisp.MISPTag()
            tag_object.from_dict(**{"name": new_tag})
        misp.tag(entity, tag_object)
    misp.untag(entity, tag_by_name[old_tag])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        default="./conf/misp_tools.ini",
        type=str,
        help="read config from here",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        dest="dry_run",
        default=False,
        action="store_true",
        help="whether to be a dry run",
    )
    # Parse options and init the logger
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Load MISP
    logger = logging.getLogger(__name__)
    misp = pymisp.PyMISP(
        url=conf.get("misp", "url"),
        key=conf.get("misp", "key"),
        ssl=conf.getboolean("misp", "verify_ssl", fallback=False),
        debug=conf.getboolean("misp", "debug", fallback=False),
    )

    # Load the galaxy manager
    all_tags = misp.tags(pythonify=True)
    all_tags_by_name = {x.name: x for x in all_tags}
    galaxy_names = get_galaxy_names_from_tag_names(all_tags_by_name.keys())
    galaxy_manager = galaxy.GalaxyManagerMISP(
        misp=misp,
        galaxy_names=galaxy_names,
    )

    # Search for tags to be replaced
    logger.info("Scanning tags")
    old_tag_to_new_tag = {}
    for galaxy_name in galaxy_manager.galaxy_names:
        # tag names coming from GALAXY CLUSTERS
        galaxy_values = galaxy_manager.get_galaxy(galaxy_name)["values"]
        galaxy_prefix = galaxy_manager.get_tag_prefix(galaxy_name)
        tag_names = [get_tag(galaxy_prefix, x["value"]) for x in galaxy_values]
        tag_synonyms = get_tag_synonyms(galaxy_values, galaxy_prefix)
        # tag names coming from MISP
        actual_tag_names = [
            x for x in all_tags_by_name if x.startswith(f"misp-galaxy:{galaxy_name}")
        ]
        for actual_tag_name in actual_tag_names:
            for tag_name in tag_names:
                should_replace = is_tag_stale__by_synonym(actual_tag_name, tag_name, tag_synonyms)
                if not should_replace and galaxy_name in SUFFIX_BASED_GALAXIES:
                    should_replace = is_tag_stale__by_suffix(actual_tag_name, tag_name)
                if should_replace:
                    logger.info(f"Tag '{actual_tag_name}' should be replaced with '{tag_name}'")
                    old_tag_to_new_tag[actual_tag_name] = tag_name

    nb_old_tags = len(old_tag_to_new_tag)
    # Search for tags in existing events
    logger.info("Processing events")
    for idx, (old_tag, new_tag) in enumerate(old_tag_to_new_tag.items(), start=1):
        logger.info(f"[{idx}/{nb_old_tags}] Replacing tag '{old_tag}' with '{new_tag}'")
        events = misp.search(
            controller="events",
            event_tags=old_tag,
            pythonify=True,
        )
        nb_events = len(events)
        for idx2, event in enumerate(events, start=1):
            logger.info(f"\t[{idx2}/{nb_events}] Processing event '{event.info}'")
            if not args.dry_run:
                search_and_replace_tag(misp, event, old_tag, new_tag)
    # Search for tags in existing attributes
    logger.info("Processing attributes")
    for idx, (old_tag, new_tag) in enumerate(old_tag_to_new_tag.items(), start=1):
        logger.info(f"[{idx}/{nb_old_tags}] Replacing tag '{old_tag}' with '{new_tag}'")
        attributes = misp.search(
            controller="attributes",
            tags=old_tag,
            pythonify=True,
        )
        nb_attributes = len(attributes)
        for idx2, attribute in enumerate(attributes, start=1):
            logger.info(f"\t[{idx2}/{nb_attributes}] Processing attribute '{attribute.uuid}'")
            if not args.dry_run:
                search_and_replace_tag(misp, attribute, old_tag, new_tag)

    return 0


if __name__ == "__main__":
    sys.exit(main())
