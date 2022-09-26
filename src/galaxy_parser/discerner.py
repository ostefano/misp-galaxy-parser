import abc
import dataclasses

from typing import cast
from typing import Dict
from typing import Tuple
from typing import List
from typing import Type
from typing import TypeVar
from typing import Optional

from galaxy_parser import galaxy
from galaxy_parser import exceptions


@dataclasses.dataclass
class Discernment:

    label: str
    discerned_name: str
    source: str
    galaxy: str
    raw_data: Dict

    def get_tag(self):
        return f"misp-galaxy:{self.galaxy}=\"{self.discerned_name}\""


class AbstractDiscerner(abc.ABC):
    """Interface for all discerners."""

    BLACKLIST = frozenset([
        "encrypted",
        "malware",
        "phishing",
        "ransomware",
        "threat",
        "trojan",
        "backdoor",
    ])

    @staticmethod
    def normalize(label: str) -> str:
        """Normalize a label removing spaces and converting to lower case."""
        return label.strip().lower().replace(" ", "").replace("-", "").replace("_", "")

    @property
    @abc.abstractmethod
    def source(self) -> str:
        """Return the source of this discernment."""

    @property
    @abc.abstractmethod
    def galaxy(self) -> str:
        """Return the galaxy of this discernment."""

    @abc.abstractmethod
    def _discern(self, label: str, include_partial_matches: bool = False) -> Tuple[str, Dict]:
        """Do the discernment."""

    def discern(self, label: str, include_partial_matches: bool = False) -> Discernment:
        """Do the discernment."""
        discerned_name, raw_data = self._discern(label, include_partial_matches)
        return Discernment(
            label=label,
            discerned_name=discerned_name,
            source=self.source,
            galaxy=self.galaxy,
            raw_data=raw_data,
        )

    def discern_compound(
        self,
        label: str,
        include_partial_matches: bool = False,
        separators: str = None
    ) -> List[Discernment]:
        """Decompose a label (useful with compound words), and then discern."""
        if not separators:
            separators = " ,"
        ret = []
        for label_fragment in label.split(separators):
            try:
                discernment = self.discern(label_fragment, include_partial_matches)
                ret.append(discernment)
            except exceptions.FailedDiscernment:
                continue
        return ret


class BaseDiscerner(AbstractDiscerner, abc.ABC):
    """Base class for standard discerners."""

    GALAXY_NAME = None

    SOURCE_NAME = None

    @classmethod
    def create_class(
        cls,
        cluster: str,
        source: Optional[str] = None,
    ) -> Type[galaxy.BaseGalaxyManagerSubType]:
        """Dynamically create a new type given a cluster name."""
        if not source:
            source = "custom"
        class_name = f"DiscernerClass_{cluster}_{source}"
        return cast(
            Type[galaxy.BaseGalaxyManagerSubType],
            type(class_name, (cls,), {'GALAXY_NAME': cluster, 'SOURCE_NAME': source})
        )

    def __init__(self, galaxy_manager: galaxy.BaseGalaxyManagerSubType) -> None:
        """Constructor."""
        galaxy_object = galaxy_manager.get_galaxy(self.GALAXY_NAME)

        # Index all values and keep track of "original" and "unique" values
        self.entry_by_normalized_label = {}
        unique_labels = set([])
        for entry in galaxy_object["values"]:
            self.entry_by_normalized_label[self.normalize(entry["value"])] = entry
            unique_labels.add(entry["value"])

        # Analyze all data entries and get the synonyms from the "meta" structure which are new
        entry_by_normalized_label_synonym = {}
        for entry in self.entry_by_normalized_label.values():
            label_synonyms = [x for x in entry.get("meta", {}).get("synonyms", [])]
            for label_synonym in label_synonyms:
                if label_synonym not in unique_labels:
                    entry_by_normalized_label_synonym[self.normalize(label_synonym)] = entry

        # Combine
        self.entry_by_normalized_label |= entry_by_normalized_label_synonym
        self.unique_normalized_labels = set(self.entry_by_normalized_label.keys())

    @property
    def source(self) -> str:
        """Implement interface."""
        return self.SOURCE_NAME

    @property
    def galaxy(self) -> str:
        """Implement interface."""
        return self.GALAXY_NAME

    def _discern(self, label: str, include_partial_matches: bool = False) -> Tuple[str, Dict]:
        """Do the discernment."""
        normalized_label = self.normalize(label)
        if normalized_label in self.BLACKLIST:
            raise exceptions.FailedDiscernment
        try:
            return (
                self.entry_by_normalized_label[normalized_label]["value"],
                self.entry_by_normalized_label[normalized_label]
            )
        except KeyError:
            if include_partial_matches:
                for unique_normalized_label in self.unique_normalized_labels:
                    if normalized_label in unique_normalized_label:
                        return (
                            self.entry_by_normalized_label[unique_normalized_label]["value"],
                            self.entry_by_normalized_label[unique_normalized_label]
                        )
            raise exceptions.FailedDiscernment


class MispActorDiscerner(BaseDiscerner):

    GALAXY_NAME = "threat-actor"

    SOURCE_NAME = "misp"


class MitreActorDiscerner(BaseDiscerner):

    GALAXY_NAME = "mitre-intrusion-set"

    SOURCE_NAME = "mitre"


class MalpediaFamilyDiscerner(BaseDiscerner):

    GALAXY_NAME = "malpedia"

    SOURCE_NAME = "malpedia"


class MispToolDiscerner(BaseDiscerner):

    GALAXY_NAME = "tool"

    SOURCE_NAME = "misp"


class MitreMalwareDiscerner(BaseDiscerner):

    GALAXY_NAME = "mitre-malware"

    SOURCE_NAME = "mitre"


class MitreToolDiscerner(BaseDiscerner):

    GALAXY_NAME = "mitre-tool"

    SOURCE_NAME = "mitre"


BaseDiscernerSubType = TypeVar("BaseDiscernerSubType", bound=BaseDiscerner)
