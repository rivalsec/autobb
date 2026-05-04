# coding=utf-8
# based on https://github.com/AlephNullSK/dnsgen
from __future__ import annotations

import itertools
import pathlib
from typing import Callable, List, Set, Iterator, Optional
from dataclasses import dataclass
import re

import tldextract
from tldextract.tldextract import ExtractResult
from dataclasses import field

# Type aliases
DomainPartsType = List[str]
PermutatorFunc = Callable[[DomainPartsType], Iterator[str]]


@dataclass
class DomainGenerator:
    """Main class for handling domain name permutations."""

    words: List[str]
    num_count: int = 3
    permutators: List[PermutatorFunc] = field(default_factory=list)
    fast_permutators: List[PermutatorFunc] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.permutators is None:
            self.permutators = []
        if self.fast_permutators is None:
            self.fast_permutators = []

    def register_permutator(self, fast: bool = False) -> Callable[[PermutatorFunc], PermutatorFunc]:
        def decorator(func: PermutatorFunc) -> PermutatorFunc:
            if fast:
                self.fast_permutators.append(func)
            self.permutators.append(func)
            return func

        return decorator

    def partiate_domain(self, domain: str) -> DomainPartsType:
        """
        Split domain based on subdomain levels.
        Root+TLD is taken as one part, regardless of its levels.

        Example:
            >>> partiate_domain("test.1.foo.example.com")
            ['test', '1', 'foo', 'example.com']
        """
        ext: ExtractResult = tldextract.extract(domain.lower())
        parts: DomainPartsType = ext.subdomain.split(".") + [ext.registered_domain]
        return parts

    def extract_custom_words(self, domains: List[str], wordlen: int) -> Set[str]:
        """
        Extract custom words from domain names based on naming conventions.
        """
        valid_tokens: Set[str] = set()

        for domain in domains:
            partition = self.partiate_domain(domain)[:-1]
            tokens = set(itertools.chain(*[word.lower().split("-") for word in partition]))
            tokens = tokens.union({word.lower() for word in partition})
            valid_tokens.update({t for t in tokens if len(t) >= wordlen})

        return valid_tokens

    @property
    def active_permutators(self) -> List[PermutatorFunc]:
        return self.fast_permutators if self.fast_mode else self.permutators

    def generate(self, domains: List[str], wordlen: int = 5, fast_mode: bool = False) -> Iterator[str]:
        """
        Generate domain permutations from provided domains.

        Yields unique permutations per input seed (dedup is per-seed, not global,
        to keep memory bounded across large seed lists).
        """
        self.fast_mode = fast_mode
        permutators = self.active_permutators

        for domain in set(domains):
            parts = self.partiate_domain(domain)
            seen: Set[str] = set()
            seen_add = seen.add
            for permutator in permutators:
                for d in permutator(parts):
                    if d in seen:
                        continue
                    seen_add(d)
                    yield d


def create_generator(wordlist_path: Optional[str | pathlib.Path] = None) -> DomainGenerator:
    """
    Create and initialize a DomainGenerator instance.
    """
    if wordlist_path is None:
        wordlist_path = pathlib.Path(__file__).parent / "words.txt"

    if isinstance(wordlist_path, str):
        wordlist_path = pathlib.Path(wordlist_path)

    with open(wordlist_path) as f:
        lines = f.read().splitlines()
        words = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]

    generator = DomainGenerator(words=words)

    @generator.register_permutator()
    def insert_word_every_index(parts: DomainPartsType) -> Iterator[str]:
        """
        Insert words between existing domain levels.
            Input:  "api.example.com"
            Output: "staging.api.example.com"
                   "api.staging.example.com"
        """
        prefix = parts[:-1]
        tld_dot = "." + parts[-1]
        # Pre-compute (left, right) string fragments per insertion position.
        positions = []
        n = len(parts)
        for i in range(n):
            left = ".".join(prefix[:i])
            right = ".".join(prefix[i:])
            left_part = left + "." if left else ""
            right_part = "." + right if right else ""
            positions.append((left_part, right_part))

        words = generator.words
        for left, right in positions:
            for w in words:
                yield left + w + right + tld_dot

    @generator.register_permutator(fast=True)
    def modify_numbers(parts: DomainPartsType) -> Iterator[str]:
        """
        Increase and decrease numbers found in domain parts.
            Input:  "api2.example.com"
            Output: "api1.example.com", "api3.example.com", ...
        """
        parts_joined = ".".join(parts[:-1])
        if not parts_joined:
            return
        # Dedup digit strings — repeats would emit identical permutations.
        digits = list(dict.fromkeys(re.findall(r"\d{1,3}", parts_joined)))
        if not digits:
            return
        tld_dot = "." + parts[-1]
        num_count = generator.num_count

        for d in digits:
            width = len(d)
            base = int(d)
            for m in range(num_count):
                replacement = str(base + 1 + m).zfill(width)
                yield parts_joined.replace(d, replacement) + tld_dot
            for m in range(num_count):
                new_digit = base - 1 - m
                if new_digit < 0:
                    break
                replacement = str(new_digit).zfill(width)
                yield parts_joined.replace(d, replacement) + tld_dot

    @generator.register_permutator()
    def environment_prefix(parts: DomainPartsType) -> Iterator[str]:
        """
        Add common environment prefixes to domain parts.
        """
        environments = ("dev", "staging", "uat", "prod", "test")
        mid = ("." + ".".join(parts[:-1])) if len(parts) > 1 else ""
        tld_dot = "." + parts[-1]
        for env in environments:
            yield env + mid + tld_dot

    @generator.register_permutator()
    def cloud_provider_additions(parts: DomainPartsType) -> Iterator[str]:
        """
        Add common cloud provider related subdomains.
        """
        cloud_terms = ("aws", "azure", "gcp", "k8s", "cloud")
        service_terms = ("api", "cdn", "storage", "auth", "db")
        mid = ("." + ".".join(parts[:-1])) if len(parts) > 1 else ""
        tld_dot = "." + parts[-1]
        for term in cloud_terms:
            for service in service_terms:
                yield service + "-" + term + mid + tld_dot

    @generator.register_permutator()
    def region_prefixes(parts: DomainPartsType) -> Iterator[str]:
        """
        Add common region/location prefixes to domain parts.
        """
        regions = ("us-east", "us-west", "eu-west", "eu-central",
                   "ap-south", "ap-northeast", "sa-east", "af-south")
        mid = ("." + ".".join(parts[:-1])) if len(parts) > 1 else ""
        tld_dot = "." + parts[-1]
        for region in regions:
            yield region + mid + tld_dot

    @generator.register_permutator()
    def microservice_patterns(parts: DomainPartsType) -> Iterator[str]:
        """
        Add common microservice naming patterns.
        """
        services = ("auth", "user", "payment", "notification", "order", "inventory")
        suffixes = ("service", "svc", "api", "app")
        mid = ("." + ".".join(parts[:-1])) if len(parts) > 1 else ""
        tld_dot = "." + parts[-1]
        for service in services:
            for suffix in suffixes:
                yield service + "-" + suffix + mid + tld_dot

    @generator.register_permutator()
    def internal_tooling(parts: DomainPartsType) -> Iterator[str]:
        """
        Add common internal tool and platform subdomains. Tokens go AFTER the
        existing prefix (before TLD), in both orders.
        """
        tools = ("jenkins", "gitlab", "grafana", "kibana", "prometheus", "monitoring", "jira")
        prefixes = ("internal", "tools", "admin")
        head = (".".join(parts[:-1]) + ".") if len(parts) > 1 else ""
        tld_dot = "." + parts[-1]
        for tool in tools:
            for prefix in prefixes:
                yield head + prefix + "." + tool + tld_dot
                yield head + tool + "." + prefix + tld_dot

    @generator.register_permutator(fast=True)
    def common_ports(parts: DomainPartsType) -> Iterator[str]:
        """
        Add common port numbers as prefixes.
        """
        ports = ("8080", "8443", "3000", "5000", "9000", "8888")
        mid = ("." + ".".join(parts[:-1])) if len(parts) > 1 else ""
        tld_dot = "." + parts[-1]
        for port in ports:
            yield port + mid + tld_dot
            yield "port-" + port + mid + tld_dot

    return generator
