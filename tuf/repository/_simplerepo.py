# Copyright 2021-2022 python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Simple example of using the repository library to build a repository"""

import copy
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from typing import Dict
import os

from securesystemslib.signer import CryptoSigner, Key, Signer

from tuf.api.exceptions import RepositoryError
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    RootVerificationResult,
    Signed,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
    VerificationResult,
)
from tuf.repository import Repository
from hashlib import sha256
from pathlib import Path

logger = logging.getLogger(__name__)

# logging.basicConfig(
#     level=logging.DEBUG,  # Set logging level to DEBUG for detailed logs
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Customize log format
# )

# logger.setLevel(logging.DEBUG)


_signed_init = {
    Root.type: Root,
    Snapshot.type: Snapshot,
    Targets.type: Targets,
    Timestamp.type: Timestamp,
}


class SimpleRepository(Repository):
    """Very simple in-memory repository implementation

    This repository keeps the metadata for all versions of all roles in memory.
    It also keeps all target content in memory.


    Attributes:
        role_cache: Every historical metadata version of every role in this
            repository. Keys are role names and values are lists of Metadata
        signer_cache: All signers available to the repository. Keys are role
            names, values are lists of signers
        target_cache: All target files served by the repository. Keys are
            target paths and values are file contents as bytes.
    """

    expiry_period = timedelta(days=1)

    def _build_key_dir(self, base_url: str) -> str:
        """build a unique and reproducible private key dir for the repository url"""
        name = sha256(base_url.encode()).hexdigest()[:8]
        # TODO: Make this not windows hostile?
        return f"{Path.home()}/.config/tuf-upload-example/{name}"

    def __init__(self, base_url: str) -> None:
        # all versions of all metadata
        self.role_cache: dict[str, list[Metadata]] = defaultdict(list)
        # all current keys
        self.signer_cache: dict[str, list[Signer]] = defaultdict(list)
        # all target content
        self.target_cache: dict[str, bytes] = {}
        # version cache for snapshot and all targets, updated in close().
        # The 'defaultdict(lambda: ...)' trick allows close() to easily modify
        # the version without always creating a new MetaFile
        self._snapshot_info = MetaFile(1)
        self._targets_infos: dict[str, MetaFile] = defaultdict(
            lambda: MetaFile(1)
        )

        # Update Keys as per ITE-2

        root_targets_key = CryptoSigner.generate_ecdsa()
        timestamp_snapshot_key = CryptoSigner.generate_ecdsa()
        signers: Dict[str, Signer] = {}
        signers["targets"] = root_targets_key
        signers["root"] = root_targets_key
        signers["snapshot"] = timestamp_snapshot_key
        signers["timestamp"] = timestamp_snapshot_key
        signers["claimed-package-signer"] = root_targets_key
        signers["unclaimed-package-signer"] = timestamp_snapshot_key

        for role in ["root", "timestamp", "snapshot", "targets",
                     "claimed-package-signer", "unclaimed-package-signer"]:
            self.signer_cache[role].append(signers[role])
        # setup a basic repository, generate signing key per top-level role
        with self.edit_root() as root:
            for role in ["root", "timestamp", "snapshot", "targets"]:
                root.add_key(signers[role].public_key, role)

        for role in ["timestamp", "snapshot", "targets"]:
            with self.edit(role):
                pass
        
        delgatee_name = "claimed-package-signer"
        self.submit_delegation(delgatee_name,
                               json.dumps({root_targets_key.public_key.keyid:
                                           root_targets_key.public_key.to_dict()}),
                               [ "packages/claimed/*/*" ])

        # HACK: share the timestamp key with uploader
        # Store the private key using rolename as filename
        keydir = self._build_key_dir(base_url)
        if not os.path.isdir(keydir):
            os.makedirs(keydir)
        with open(f"{keydir}/{delgatee_name}", "wb") as f:
            f.write(root_targets_key.private_bytes)

        print(f"Uploaded new delegation, stored key in {keydir}/{delgatee_name}")

        delgatee_name = "unclaimed-package-signer"
        self.submit_delegation(delgatee_name,
                               json.dumps({timestamp_snapshot_key.public_key.keyid:
                                           timestamp_snapshot_key.public_key.to_dict()}),
                               [ "packages/unclaimed/*/*" ])

        # HACK: share the timestamp key with uploader
        # Store the private key using rolename as filename
        keydir = self._build_key_dir(base_url)
        if not os.path.isdir(keydir):
            os.makedirs(keydir)
        with open(f"{keydir}/{delgatee_name}", "wb") as f:
            f.write(timestamp_snapshot_key.private_bytes)

        print(f"Uploaded new delegation, stored key in {keydir}/{delgatee_name}")

    @property
    def targets_infos(self) -> dict[str, MetaFile]:
        return self._targets_infos

    @property
    def snapshot_info(self) -> MetaFile:
        return self._snapshot_info

    def _get_verification_result(
        self, role: str, md: Metadata
    ) -> Union[VerificationResult, RootVerificationResult]:
        """Verify roles metadata using the existing repository metadata"""
        if role == Root.type:
            assert isinstance(md.signed, Root)
            root = self.root()
            previous = root if root.version > 0 else None
            return md.signed.get_root_verification_result(
                previous, md.signed_bytes, md.signatures
            )
        if role in [Timestamp.type, Snapshot.type, Targets.type]:
            delegator: Signed = self.root()
        elif role in ["claimed-package-signer", "unclaimed-package-signer"]:
            delegator = self.targets()
        else:
            if "unclaimed" in next(iter(md.to_dict()['signed']['targets'])):
                delegator = self.targets("unclaimed-package-signer")
            elif "claimed" in next(iter(md.to_dict()['signed']['targets'])):
                delegator = self.targets("claimed-package-signer")
            else:
                delegator = self.targets()
        return delegator.get_verification_result(
            role, md.signed_bytes, md.signatures
        )

    def open(self, role: str) -> Metadata:
        """Return current Metadata for role from 'storage'
        (or create a new one)
        """

        if role not in self.role_cache:
            signed_init = _signed_init.get(role, Targets)
            md = Metadata(signed_init())

            # this makes version bumping in close() simpler
            md.signed.version = 0
            return md

        # return latest metadata from storage (but don't return a reference)
        return copy.deepcopy(self.role_cache[role][-1])

    def close(self, role: str, md: Metadata) -> None:
        """Store a version of metadata. Handle version bumps, expiry, signing"""
        md.signed.version += 1
        md.signed.expires = datetime.now(timezone.utc) + self.expiry_period

        md.signatures.clear()
        for signer in self.signer_cache[role]:
            md.sign(signer, append=True)

        # Double check that we only write verified metadata
        vr = self._get_verification_result(role, md)
        if not vr:
            raise ValueError(f"Role {role} failed to verify")
        keyids = [keyid[:7] for keyid in vr.signed]
        verify_str = f"verified with keys [{', '.join(keyids)}]"
        logger.debug("Role %s v%d: %s", role, md.signed.version, verify_str)

        # store new metadata version, update version caches
        self.role_cache[role].append(md)
        if role == "snapshot":
            self._snapshot_info.version = md.signed.version
        elif role not in ["root", "timestamp"]:
            self._targets_infos[f"{role}.json"].version = md.signed.version

    def add_target(self, path: str, content: str, custom_metadata: Optional[dict] = None) -> None:
        """Add a target to top-level targets metadata"""
        data = bytes(content, "utf-8")

        # add content to cache for serving to clients
        self.target_cache[path] = data

        # add a target in the targets metadata
        with self.edit_targets() as targets:
            targets.targets[path] = TargetFile.from_data(path, data)
            if custom_metadata:
                targets.targets[path].unrecognized_fields = custom_metadata

        # update snapshot, timestamp
        self.do_snapshot()
        self.do_timestamp()

    def submit_delegation(self, rolename: str, data: bytes, paths: Optional[list[str]] = None) -> bool:
        """Add a delegation to a (offline signed) delegated targets metadata"""
        try:
            logger.debug("Processing new delegation to role %s", rolename)
            keyid, keydict = next(iter(json.loads(data).items()))
            key = Key.from_dict(keyid, keydict)


            if paths is None:
                paths = [f"{rolename}/*"]
            # add delegation and key
            role = DelegatedRole(rolename, [], 1, True, paths)
            with self.edit_targets() as targets:
                if targets.delegations is None:
                    targets.delegations = Delegations({}, {})
                if targets.delegations.roles is None:
                    targets.delegations.roles = {}
                targets.delegations.roles[rolename] = role
                targets.add_key(key, rolename)

        except (RepositoryError, json.JSONDecodeError) as e:
            logger.info("Failed to add delegation for %s: %s", rolename, e)
            return False

        # update snapshot, timestamp
        self.do_snapshot()
        self.do_timestamp()
        
        return True

    def submit_delegation_claimed(self, rolename: str, data: bytes, paths: Optional[list[str]] = None) -> bool:
        """Add a delegation to a (offline signed) delegated targets metadata"""
        try:
            logger.debug("Processing new delegation to role %s", rolename)
            keyid, keydict = next(iter(json.loads(data).items()))
            key = Key.from_dict(keyid, keydict)


            if paths is None:
                paths = [f"packages/claimed/{rolename}/*"]
            # add delegation and key
            role = DelegatedRole(rolename, [], 1, True, paths)
            with self.edit_targets("claimed-package-signer") as targets:
                if targets.delegations is None:
                    targets.delegations = Delegations({}, {})
                if targets.delegations.roles is None:
                    targets.delegations.roles = {}
                targets.delegations.roles[rolename] = role
                targets.add_key(key, rolename)

        except (RepositoryError, json.JSONDecodeError) as e:
            logger.info("Failed to add delegation for %s: %s", rolename, e)
            return False

        # update snapshot, timestamp
        self.do_snapshot()
        self.do_timestamp()
        
        return True

    def submit_delegation_unclaimed(self, rolename: str, data: bytes, paths: Optional[list[str]] = None) -> bool:
        """Add a delegation to a (offline signed) delegated targets metadata"""
        try:
            logger.debug("Processing new delegation to role %s", rolename)
            keyid, keydict = next(iter(json.loads(data).items()))
            key = Key.from_dict(keyid, keydict)


            if paths is None:
                paths = [f"packages/unclaimed/{rolename}/*"]
            # add delegation and key
            role = DelegatedRole(rolename, [], 1, True, paths)
            with self.edit_targets("unclaimed-package-signer") as targets:
                if targets.delegations is None:
                    targets.delegations = Delegations({}, {})
                if targets.delegations.roles is None:
                    targets.delegations.roles = {}
                targets.delegations.roles[rolename] = role
                targets.add_key(key, rolename)

        except (RepositoryError, json.JSONDecodeError) as e:
            logger.info("Failed to add delegation for %s: %s", rolename, e)
            return False

        # update snapshot, timestamp
        self.do_snapshot()
        self.do_timestamp()
        
        return True

    def submit_role(self, role: str, data: bytes) -> bool:
        """Add a new version of a delegated roles metadata"""
        try:
            logger.debug("Processing new version for role %s", role)
            if role in ["root", "snapshot", "timestamp", "targets"]:
                raise ValueError("Only delegated targets are accepted")

            md = Metadata.from_bytes(data)
            # for targetpath in md.signed.targets:
            #     # Robusto: allow any path for packages-and-in-toto-metadata-signer
            #     if not targetpath.startswith(f"{role}/") and role != "packages-and-in-toto-metadata-signer":
            #         raise ValueError(f"targets allowed under {role}/ only")

            if md.signed.version != self.targets(role).version + 1:
                raise ValueError("Invalid version {md.signed.version}")

        except (RepositoryError, ValueError) as e:
            logger.info("Failed to add new version for %s: %s", role, e)
            return False

        # Check that we only write verified metadata
        vr = self._get_verification_result(role, md)
        if not vr:
            logger.info("Role %s failed to verify", role)
            return False

        keyids = [keyid[:7] for keyid in vr.signed]
        verify_str = f"verified with keys [{', '.join(keyids)}]"
        logger.debug("Role %s v%d: %s", role, md.signed.version, verify_str)

        # Checks passed: Add new delegated role version
        self.role_cache[role].append(md)
        self._targets_infos[f"{role}.json"].version = md.signed.version

        # To keep it simple, target content is generated from targetpath
        for targetpath in md.signed.targets:
            self.target_cache[targetpath] = bytes(f"{targetpath}", "utf-8")
                
        # update snapshot, timestamp
        self.do_snapshot()
        self.do_timestamp()

        return True
