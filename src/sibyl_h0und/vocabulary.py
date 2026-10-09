"""The knowledge vocabulary the model can consult through `lookup_knowledge`.

The model decides what in the evidence is odd and what to look up. This module
only retrieves: it finds what the committed packs say about a term and returns
the entries as they are, each under the name of its source. It rates nothing,
orders nothing by importance and says nothing about whether a term is good or
bad (ADR 0017). An empty answer means the sources have no entry, not that the
term is safe.

A query is one string. It is matched the same way whatever it is:

- an ATT&CK id (`T1036.003`, `S0195`) finds the technique or software, and a
  technique brings the software documented to use it and, by platform, the data
  components ATT&CK's detection analytics read for it;
- a file name or path finds entries by normalized program name, and a name
  with a version or `.exe` is reduced the same way the packs were built;
- a domain finds the RMM tool of that domain or of a parent domain;
- a driver file name (`RTCore64.sys`) or a SHA-256 finds the LOLDrivers entries, and a DLL
  name finds the HijackLibs entries with the locations of the legitimate copy;
- a Unix program name or path finds the GTFOBins and GTFOArgs entries (`curl`,
  `/usr/bin/find`);
- an absolute Windows path or a file extension finds the rows of the Nextron
  antivirus cheat sheet;
- a registry key path (`HKLM\\...`, `HKCU\\...`) finds the autostart locations of
  ForensicArtifacts that are the key or one of its parents;
- any words find the techniques, software and WTFBins entries that share them.

A query with spaces is a description. Besides its words, each term in it is
looked up on its own: an id, a file name, a path, a domain, a hash, a SID or an
extension as above. A bare word of a description that is exactly the name of a
Windows program in a source (`vssadmin`, but also `play`, the name of a
ransomware) is only named in `names`: whether the word means the program is the
model's call, and it gets the entry by looking the name up on its own or in
`terms`. More terms can come in `terms` in the same lookup. When a lookup makes
more than one search, each entry says which `term` found it; at most
`TERM_LIMIT` searches of one lookup give entries.
"""

import json
import re
from collections import defaultdict
from collections.abc import Iterable
from functools import cache
from typing import Any

from sibyl_h0und.knowledge import load_pack
from sibyl_h0und.nextron import extension_row, location_row, user_row
from sibyl_h0und.normalize import (
    attack_id,
    domain,
    file_key,
    program_name,
    registry_path,
    unix_program,
)

KNOWLEDGE_TOOL = "lookup_knowledge"
KNOWLEDGE_TOOL_SPEC: dict[str, Any] = {
    "name": KNOWLEDGE_TOOL,
    "description": (
        "Look up a term in local security knowledge, with no cost to the investigation: "
        "MITRE ATT&CK techniques and software, LOLBAS and GTFOBins (abusable Windows and Unix "
        "binaries), GTFOArgs (abusable Unix arguments), LOLRMM remote management tools, "
        "WTFBins benign programs that look suspicious, ForensicArtifacts Windows autostart "
        "registry locations, LOLDrivers abusable drivers, HijackLibs DLL hijacking "
        "opportunities, and the Nextron antivirus cheat sheet. "
        "The query is an ATT&CK id (T1036.003, S0195), a file name or path, a SHA-256, "
        "a registry key path, a domain, or words describing behavior. Several terms can be "
        "looked up at once in `terms`. A word of a description that is a program name in "
        "a source is listed in `names`; look it up for its entry. Entries are returned as "
        "the sources state them, with no verdict."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "Term to look up, such as sdelete.exe, T1036.003 or rename system utility."
                ),
            },
            "terms": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "More terms to look up in the same call, one term each, such as "
                    "vssadmin.exe and T1490."
                ),
            },
        },
        "required": ["query"],
    },
}

# Most software entries that use a technique, and entries per kind of a word match.
LIMIT = 5
WORD_LIMIT = 3
# Most searches of one lookup that give entries: a term, a term inside a description
# or the words of a description. A search with no entry adds nothing to the answer.
# Also the most program names one lookup lists in `names`.
TERM_LIMIT = 10
# Words too common to say what a query is about.
STOP_WORDS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "by", "can", "for", "from", "has", "have",
        "in", "is", "it", "its", "of", "on", "or", "that", "the", "this", "to", "was", "were",
        "with", "use", "used", "using", "adversaries", "adversary", "may",
    }
)  # fmt: skip
_TOKEN = re.compile(r"[a-z0-9][a-z0-9.+#-]{1,}")
_ABSOLUTE_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_SID = re.compile(r"^S-1-\d+(?:-\d+)+$", re.IGNORECASE)
_EXTENSION = re.compile(r"^\.[A-Za-z0-9]{1,8}$")
_WINDOWS_FILE = re.compile(r"\.(?:exe|dll|sys|bat|cmd|ps1|vbs|msi|com|scr)$", re.IGNORECASE)
_PLAIN_WORD = re.compile(r"^[A-Za-z][A-Za-z-]*$")
_BARE_WORD = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_DIGEST = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
_UNIX_PATH = re.compile(r"^/[^/]+/")
# A whole query that is a Unix path, spaces allowed inside but not in its first or
# last component: `/opt/my tools/bin/nc` is a path, `/tmp/x was run by curl` is not.
_WHOLE_UNIX_PATH = re.compile(r"^/[^/\s]+/(?:[^/]*/)*[^/\s]+$")
# Punctuation around a term in a description: `(vssadmin.exe),` is `vssadmin.exe`.
_EDGE = "\"'`()[]{}<>,;:!?"
# Words of a query a text must share for a word match.
MIN_WORD_MATCHES = 2
# A word in a name says more about what an entry is than one in its summary.
NAME_WEIGHT = 3


def _file_name(text: str) -> str | None:
    """Return the file name a query names, or `None` when it is not one.

    A query is a file name when it has no space, or when it is a path whose last
    component has none (`C:\\Program Files\\AnyDesk\\AnyDesk.exe`). A command line
    or a sentence is not.
    """
    last = re.split(r"[\\/]", text.strip().strip('"'))[-1].strip()
    return last if last and " " not in last else None


def _is_windows(text: str) -> bool:
    """Tell whether a query is a Windows path or a Windows executable name."""
    return bool(_ABSOLUTE_PATH.match(text) and not text.startswith("/")) or bool(
        _WINDOWS_FILE.search(text.strip().strip('"'))
    )


def stem(word: str) -> str:
    """Cut a plural ending, so `utilities` and `utility` meet."""
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def tokens(text: Any) -> set[str]:
    """Return the lower-cased, stemmed words of a text that can say what it is about.

    A hyphenated word also gives its parts, so `pass-the-hash` meets "Pass the Hash".
    """
    if not isinstance(text, str):
        return set()
    words = set()
    for word in _TOKEN.findall(text.lower()):
        parts = [word, *word.split("-")] if "-" in word else [word]
        words |= {stem(part) for part in parts if len(part) > 1 and part not in STOP_WORDS}
    return words


def _terms_in(text: str) -> list[tuple[str, bool]]:
    """Return the terms of a description, each with whether it is a bare word.

    A term is an ATT&CK id, a digest, a SID, an extension, a registry key, an
    absolute path, or a name with a dot (a file name or a domain). Any other word
    is a bare word: it may or may not be the name of a program.
    """
    found: dict[str, bool] = {}
    for raw in text.split():
        token = raw
        while (trimmed := token.strip(_EDGE).rstrip(".")) != token:
            token = trimmed
        if not token or token in found:
            continue
        if (
            attack_id(token)
            or _DIGEST.match(token)
            or _SID.match(token)
            or _EXTENSION.match(token)
            or registry_path(token)
            or _ABSOLUTE_PATH.match(token)
            or _UNIX_PATH.match(token)
            or "." in token
        ):
            found[token] = False
        elif _BARE_WORD.match(token):
            found[token] = True
    return list(found.items())


def _unquote(text: str) -> str:
    """Strip whitespace and one pair of double quotes around a whole query."""
    text = text.strip()
    if len(text) > 1 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    return text


def _label(entry: dict[str, Any]) -> str:
    """Name an entry in a few words: its source and its id or name."""
    parts = [entry["source"], entry.get("id"), entry.get("name") or entry.get("title")]
    return " ".join(str(part) for part in parts if part)


def _same_entry(item: dict[str, Any]) -> str:
    """Return what identifies an entry whichever term found it."""
    return json.dumps({k: v for k, v in item.items() if k != "term"}, sort_keys=True, default=str)


class Vocabulary:
    """Look terms up across the committed knowledge packs."""

    def __init__(self) -> None:
        """Load the packs and index the techniques each software uses."""
        self._techniques = load_pack("attack_techniques")
        self._software = load_pack("attack_software")
        self._software_names = load_pack("attack_software_names")
        self._lolbas = load_pack("lolbas")
        self._lolrmm = load_pack("lolrmm")
        self._lolrmm_domains = load_pack("lolrmm_domains")
        self._wtfbins = load_pack("wtfbins")
        self._gtfobins = load_pack("gtfobins")
        self._gtfoargs = load_pack("gtfoargs")
        self._autostart = load_pack("forensicartifacts_autostart")
        self._loldrivers = load_pack("loldrivers")
        self._hijacklibs = load_pack("hijacklibs")
        self._wtfbin_by_id = {doc["id"]: doc for doc in self._wtfbins.documents}
        self._gtfobins_notes = {doc["id"]: doc for doc in self._gtfobins.documents}
        self._users_of: dict[str, list[str]] = defaultdict(list)
        for software_id, entry in sorted(self._software.entries.items()):
            for technique_id in entry["techniques"]:
                self._users_of[technique_id].append(software_id)
        self._words: dict[str, tuple[set[str], set[str]]] = {
            **{
                key: (tokens(entry["name"]), tokens(entry["summary"]))
                for key, entry in {
                    **self._techniques.entries,
                    **self._software.entries,
                }.items()
            },
            **{
                f"wtfbins:{doc['id']}": (tokens(doc["title"]), tokens(doc["summary"]))
                for doc in self._wtfbin_by_id.values()
            },
        }

    def lookup(self, query: Any, terms: Any = ()) -> dict[str, Any]:
        """Return what the sources say about a query and any more terms.

        Args:
            query: The model's term, as given.
            terms: More terms of the same lookup, as given.

        Returns:
            `query`, `matches` (entries, each with its `source`) and, when
            there are none, a `note` that the sources have no entry. When the
            lookup made more than one search, each entry has the `term` that
            found it, `not_found` lists the asked terms with no entry, and
            `skipped` the searches not made once `TERM_LIMIT` searches gave entries.
            `names` lists the bare words of a description that a source has
            a program by, with the entries they would bring.
        """
        text = query.strip() if isinstance(query, str) else ""
        extra = [terms] if isinstance(terms, str) else terms if isinstance(terms, list) else []
        stripped = (_unquote(item) for item in (text, *extra) if isinstance(item, str))
        asked = list(dict.fromkeys(item for item in stripped if item))
        searches = [(item, *search) for item in asked for search in self._searches(item)]
        tagged = sum(how != "name" for _, _, how in searches) > 1
        asked_names = {item.lower() for item in asked}
        matches: list[dict[str, Any]] = []
        seen: set[str] = set()
        answered: set[str] = set()
        skipped: list[str] = []
        names: dict[str, list[str]] = {}
        with_entries = 0
        for item, term, how in searches:
            if how == "name":
                # Named, not answered: the model decides whether the word is the program.
                key = term.lower()
                if key in names or key in asked_names or len(names) >= TERM_LIMIT:
                    continue
                if found := self._by_program(f"{term}.exe"):
                    names[key] = [_label(entry) for entry in found]
                    answered.add(item)
                continue
            if with_entries >= TERM_LIMIT:
                skipped.append(term)
                continue
            if how == "words":
                found = self._by_words(term, matches)
            else:
                found = self._by_term(term)
                if not found and _PLAIN_WORD.match(term):
                    found = self._by_words(term, matches)
            with_entries += bool(found)
            for entry in found:
                answered.add(item)
                entry = {"term": term, **entry} if tagged else entry
                if (key := _same_entry(entry)) not in seen:
                    seen.add(key)
                    matches.append(entry)
        answer: dict[str, Any] = {"query": text, "matches": matches}
        given = {_label(entry) for entry in matches}
        # A name whose entries the answer already gives needs no second lookup.
        names = {term: found for term, found in names.items() if not set(found) <= given}
        unsearched = {item for item, term, _ in searches if term in skipped}
        not_found = [item for item in asked if item not in answered | unsearched]
        if not_found and len(asked) > 1 and (matches or names):
            answer["not_found"] = not_found
        if names:
            answer["names"] = [{"term": term, "entries": found} for term, found in names.items()]
            answer["names_note"] = (
                "Words of the query that are a program name in a source. Look a name up "
                "on its own or in `terms` if you mean the program."
            )
        if skipped:
            answer["skipped"] = skipped
        if not matches and not names:
            answer["note"] = (
                "No entry in ATT&CK, LOLBAS, GTFOBins, GTFOArgs, LOLRMM, WTFBins, "
                "ForensicArtifacts, LOLDrivers, HijackLibs or the Nextron cheat sheet. "
                "That says nothing about whether the term is benign or hostile."
            )
        return answer

    def _searches(self, text: str) -> list[tuple[str, str]]:
        """Return the searches for one asked term: the term, or a description's terms and words."""
        if not self._is_description(text):
            return [(text, "term")]
        terms = [(term, "name" if bare else "term") for term, bare in _terms_in(text)]
        return [*terms, (text, "words")]

    def _by_term(self, text: str) -> list[dict[str, Any]]:
        """Find the entries of one term: an id, a path, a file name, a domain or a key."""
        found = self._by_id(text)
        if registry_path(text):
            found += self._by_registry(text)
        else:
            found += self._by_program(text)
            found += self._by_driver(text)
        found += self._by_domain(text)
        found += self._by_cheat_sheet(text)
        return found

    def _named_techniques(self, ids: Iterable[str]) -> list[dict[str, Any]]:
        """Give each technique id with its ATT&CK name, `None` when the pack lacks it."""
        return [
            {"id": item, "name": (self._techniques.entries.get(item) or {}).get("name")}
            for item in ids
        ]

    def technique(self, technique_id: str) -> dict[str, Any] | None:
        """Return a technique with the software documented to use it."""
        entry = self._techniques.entries.get(technique_id)
        if entry is None:
            return None
        users = [
            {"id": software_id, "name": self._software.entries[software_id]["name"]}
            for software_id in self._users_of.get(technique_id, ())
        ]
        return {
            "source": "attack",
            "kind": "technique",
            "id": technique_id,
            **entry,
            "software_using_it": users[: LIMIT * 4],
            "software_using_it_total": len(users),
        }

    def software(self, software_id: str) -> dict[str, Any] | None:
        """Return a software entry with the names of the techniques it uses."""
        entry = self._software.entries.get(software_id)
        if entry is None:
            return None
        techniques = self._named_techniques(
            technique_id
            for technique_id in entry["techniques"]
            if technique_id in self._techniques.entries
        )
        return {
            "source": "attack",
            "kind": entry["type"],
            "id": software_id,
            **{key: value for key, value in entry.items() if key != "techniques"},
            "techniques": techniques,
        }

    def _by_id(self, text: str) -> list[dict[str, Any]]:
        """Find a technique or software by its ATT&CK id."""
        if (key := attack_id(text)) is None:
            return []
        found = self.technique(key) if key.startswith("T") else self.software(key)
        return [found] if found else []

    def _by_program(self, text: str) -> list[dict[str, Any]]:
        """Find entries whose program name equals the query's file name."""
        if (file_name := _file_name(text)) is None or (name := program_name(file_name)) is None:
            return []
        found = [] if _is_windows(text) else self._unix(file_name)
        alias = self._software_names.entries.get(name)
        if alias is not None and (software := self.software(alias["id"])) is not None:
            found.append(software)
        if (entry := self._lolbas.entries.get(name)) is not None:
            techniques = self._named_techniques(entry.get("mitre", []))
            found.append(
                {
                    "source": "lolbas",
                    "kind": "binary",
                    "name": name,
                    "categories": entry["categories"],
                }
                | ({"techniques": techniques} if techniques else {})
            )
        if (entry := self._lolrmm.entries.get(name)) is not None:
            found.append({"source": "lolrmm", "kind": "rmm_executable", "name": name, **entry})
        for doc in self._wtfbins.entries.get(name, ()):
            found.append({"source": "wtfbins", "kind": "benign_but_suspicious", **doc})
        if (entries := self._hijacklibs.entries.get(name)) is not None:
            found.append(
                {"source": "hijacklibs", "kind": "dll_hijack", "name": name, "entries": entries}
            )
        return found

    def _by_driver(self, text: str) -> list[dict[str, Any]]:
        """Find the LOLDrivers entries for a driver file name or a SHA-256."""
        if (file_name := _file_name(text)) is None:
            return []
        if (indexes := self._loldrivers.lookup(file_name)) is None:
            return []
        digest = file_key(file_name)
        return [
            {
                "source": "loldrivers",
                "kind": "driver",
                "matched_on": "sha256" if digest and len(digest) == 64 else "name",
                "queried": digest,
                "drivers": [self._loldrivers.documents[index] for index in indexes],
            }
        ]

    def _unix(self, text: str) -> list[dict[str, Any]]:
        """Find the GTFOBins and GTFOArgs entries of a Unix program name."""
        found: list[dict[str, Any]] = []
        if (entry := self._gtfobins.lookup(text)) is not None:
            functions = {}
            for function, example in entry["functions"].items():
                note = self._gtfobins_notes.get(function, {})
                techniques = self._named_techniques(note.get("mitre", []))
                functions[function] = {
                    "description": note.get("description"),
                    "example": example,
                    **({"techniques": techniques} if techniques else {}),
                }
            found.append(
                {
                    "source": "gtfobins",
                    "kind": "unix_binary",
                    "name": unix_program(text),
                    "functions": functions,
                    "contexts": entry["contexts"],
                }
            )
        if (entry := self._gtfoargs.lookup(text)) is not None:
            found.append(
                {
                    "source": "gtfoargs",
                    "kind": "unix_arguments",
                    "name": unix_program(text),
                    **entry,
                }
            )
        return found

    def _by_registry(self, text: str) -> list[dict[str, Any]]:
        """Find the autostart locations for a registry key: the key itself and its parents.

        An artifact that names one value of a key applies to that key only; one that
        names the key as a whole also applies to the keys below it. `relation` says
        which of the two the answer is.
        """
        path = registry_path(text)
        parts = (path or "").split("\\")
        found = []
        for end in range(len(parts), 0, -1):
            key = "\\".join(parts[:end])
            exact = end == len(parts)
            entries = [
                entry
                for entry in self._autostart.entries.get(key, ())
                if exact or "value" not in entry
            ]
            if entries:
                found.append(
                    {
                        "source": "forensicartifacts",
                        "kind": "autostart_location",
                        "key": key,
                        "relation": "same_key" if exact else "key_is_below",
                        "queried": text,
                        "artifacts": entries,
                    }
                )
        return found

    def _by_domain(self, text: str) -> list[dict[str, Any]]:
        """Find the RMM tool of a domain or of one of its parent domains."""
        if (host := domain(text)) is None:
            return []
        labels = host.split(".")
        for start in range(len(labels) - 1):
            parent = ".".join(labels[start:])
            if (entry := self._lolrmm_domains.entries.get(parent)) is not None:
                return [
                    {"source": "lolrmm", "kind": "rmm_domain", "domain": parent, "queried": host}
                    | entry
                ]
        return []

    @staticmethod
    def _by_cheat_sheet(text: str) -> list[dict[str, Any]]:
        """Give the Nextron cheat sheet rows for a path, an extension or an account SID."""
        rows: dict[str, Any] = {}
        if _ABSOLUTE_PATH.match(text):
            rows["location"] = location_row(text)
            rows["extension"] = extension_row(text)
        elif _EXTENSION.match(text):
            rows["extension"] = extension_row("file" + text)
        elif _SID.match(text):
            rows["account"] = user_row(text)
        rows = {name: row for name, row in rows.items() if row is not None}
        return [{"source": "nextron", "kind": "cheat_sheet", "query": text, **rows}] if rows else []

    @staticmethod
    def _is_description(text: str) -> bool:
        """Tell whether a query is words, not an id, a path, a SID, a domain or a file name."""
        text = text.strip().strip('"').strip()
        structured = (
            attack_id(text)
            or _ABSOLUTE_PATH.match(text)
            or _WHOLE_UNIX_PATH.match(text)
            or _SID.match(text)
            or registry_path(text)
        )
        return not structured and " " in text

    def _by_words(self, text: str, already: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Find techniques, software and WTFBins entries that share words with the query."""
        query = tokens(text)
        if not query:
            return []
        # Words as written: the parts of `pass-the-hash` are one word, not three.
        written = len({word for word in _TOKEN.findall(text.lower()) if word not in STOP_WORDS})
        shown = {(item.get("source"), item.get("id")) for item in already}
        scored = []
        for key, (name_words, summary_words) in self._words.items():
            name_hits, summary_hits = len(query & name_words), len(query & summary_words)
            enough = len(query & (name_words | summary_words)) >= min(MIN_WORD_MATCHES, len(query))
            # One word alone says too little to match on an entry's summary.
            if enough and (written > 1 or name_hits):
                scored.append((-(NAME_WEIGHT * name_hits + summary_hits), key))
        scored.sort()
        found: list[dict[str, Any]] = []
        per_kind: dict[str, int] = defaultdict(int)
        for _, key in scored:
            if key.startswith("wtfbins:"):
                doc = self._wtfbin_by_id[int(key.split(":", 1)[1])]
                item = {"source": "wtfbins", "kind": "benign_but_suspicious", **doc}
                kind = "wtfbins"
            elif key.startswith("T"):
                item, kind = self.technique(key), "technique"
            else:
                item, kind = self.software(key), "software"
            if item is None or ("attack", key) in shown or per_kind[kind] >= WORD_LIMIT:
                continue
            per_kind[kind] += 1
            found.append(item)
        return found


@cache
def shared() -> Vocabulary:
    """Return the vocabulary, loaded once per process."""
    return Vocabulary()
