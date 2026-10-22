"""Fail-closed contracts used by the Phase 2 L7 record/replay executor."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


class ReplayContractError(ValueError):
    """Raised before an invalid cache or unsafe provider call can be used."""


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def response_entry(
    *, campaign_id: str, scenario_id: str, repetition: int, shared_turn_index: int,
    primary_visible_input: dict[str, Any], model_snapshot: str,
    decoding_configuration: dict[str, Any], adapter_contract_version: str,
    raw_response: bytes, typed_output: dict[str, Any], provider_request_id: str,
    provider_total_tokens: int, finish_reason: str, ignored_provider_fields: Iterable[str] = (),
) -> dict[str, Any]:
    if not campaign_id or not scenario_id or repetition < 1 or shared_turn_index < 1:
        raise ReplayContractError("REPLAY_KEY_INVALID")
    if not model_snapshot or not adapter_contract_version or not provider_request_id or provider_total_tokens < 0:
        raise ReplayContractError("REPLAY_PROVENANCE_INVALID")
    input_sha=canonical_sha256(primary_visible_input)
    entry={
        "campaign_id":campaign_id,"scenario_id":scenario_id,"repetition":repetition,
        "shared_turn_index":shared_turn_index,"primary_input_sha256":input_sha,
        "model_snapshot":model_snapshot,"decoding_config_sha256":canonical_sha256(decoding_configuration),
        "adapter_contract_version":adapter_contract_version,
        "raw_response_sha256":"sha256:"+hashlib.sha256(raw_response).hexdigest(),
        "typed_output_sha256":canonical_sha256(typed_output),"typed_output":typed_output,
        "provider_request_id":provider_request_id,"provider_total_tokens":provider_total_tokens,
        "finish_reason":finish_reason,"ignored_provider_fields":sorted(set(ignored_provider_fields)),
        "provenance":"PRIMARY_LIVE_RECORDED",
    }
    entry["cache_key_sha256"]=canonical_sha256({name:entry[name] for name in ("scenario_id","repetition","shared_turn_index","primary_input_sha256","model_snapshot","decoding_config_sha256","adapter_contract_version")})
    entry["entry_sha256"]=canonical_sha256(entry)
    return entry


def freeze_cache(path: Path, *, campaign_id: str, corpus_sha256: str, catalogue_sha256: str,
                 replay_contract_sha256: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Write once using exclusive creation; an existing campaign cache is never replaced."""
    keys=[entry.get("cache_key_sha256") for entry in entries]
    if len(keys)!=len(set(keys)) or any(not isinstance(key,str) for key in keys):
        raise ReplayContractError("REPLAY_CACHE_DUPLICATE_OR_INVALID_KEY")
    for entry in entries:
        claimed=entry.get("entry_sha256"); unsigned=dict(entry); unsigned.pop("entry_sha256",None)
        if claimed!=canonical_sha256(unsigned) or entry.get("campaign_id")!=campaign_id:
            raise ReplayContractError("REPLAY_CACHE_ENTRY_INTEGRITY_FAILURE")
    document={"schema_version":"1.0","status":"FROZEN_BEFORE_ARM_EXECUTION","campaign_id":campaign_id,
              "corpus_sha256":corpus_sha256,"catalogue_sha256":catalogue_sha256,
              "replay_contract_sha256":replay_contract_sha256,"entry_count":len(entries),
              "entries":sorted(entries,key=lambda item:item["cache_key_sha256"])}
    document["cache_sha256"]=canonical_sha256(document)
    try:
        with path.open("x",encoding="utf-8") as stream:
            stream.write(json.dumps(document,indent=2,sort_keys=True)+"\n")
    except FileExistsError as exc:
        raise ReplayContractError("REPLAY_CACHE_OVERWRITE_FORBIDDEN") from exc
    return document


def verify_cache(document: dict[str, Any], *, campaign_id: str, expected_keys: set[str] | None = None) -> dict[str, dict[str, Any]]:
    claimed=document.get("cache_sha256"); unsigned=dict(document); unsigned.pop("cache_sha256",None)
    if claimed!=canonical_sha256(unsigned) or document.get("status")!="FROZEN_BEFORE_ARM_EXECUTION" or document.get("campaign_id")!=campaign_id:
        raise ReplayContractError("REPLAY_CACHE_INTEGRITY_FAILURE")
    entries=document.get("entries")
    if not isinstance(entries,list) or document.get("entry_count")!=len(entries):
        raise ReplayContractError("REPLAY_CACHE_MEMBERSHIP_FAILURE")
    indexed={}
    for entry in entries:
        entry_claim=entry.get("entry_sha256"); entry_unsigned=dict(entry); entry_unsigned.pop("entry_sha256",None)
        key=entry.get("cache_key_sha256")
        if entry_claim!=canonical_sha256(entry_unsigned) or not isinstance(key,str) or key in indexed or entry.get("campaign_id")!=campaign_id:
            raise ReplayContractError("REPLAY_CACHE_ENTRY_INTEGRITY_FAILURE")
        indexed[key]=entry
    if expected_keys is not None and set(indexed)!=expected_keys:
        raise ReplayContractError("REPLAY_CACHE_CLOSED_MEMBERSHIP_FAILURE")
    return indexed


def shared_turn_cohorts(arm_turns: dict[str,list[dict[str,Any]]]) -> dict[str,Any]:
    """Compare only arms that still share the exact Primary-visible input; never rejoin."""
    active=set(arm_turns); compared=0; divergence=None; cohorts=[]
    maximum=max((len(turns) for turns in arm_turns.values()),default=0)
    for offset in range(maximum):
        reached={arm:turns[offset] for arm,turns in arm_turns.items() if arm in active and offset<len(turns)}
        if len(reached)<2:
            if divergence is None and active: divergence={"turn":offset+1,"reason":"TERMINATION","arms":sorted(active)}
            break
        if len(reached)!=len(active):
            divergence=divergence or {"turn":offset+1,"reason":"TERMINATION","arms":sorted(active-set(reached))}
            active=set(reached)
        groups: dict[str,list[str]]={}
        for arm,turn in reached.items(): groups.setdefault(turn["primary_input_sha256"],[]).append(arm)
        if len(groups)>1:
            divergence=divergence or {"turn":offset+1,"reason":"PRIMARY_INPUT","arms":sorted(reached)}
            active=set()  # Never rejoin after treatment-induced history differs.
            break
        entries={turn.get("cache_key_sha256") for turn in reached.values()}
        outputs={turn.get("typed_output_sha256") for turn in reached.values()}
        if len(entries)!=1 or len(outputs)!=1:
            raise ReplayContractError("SHARED_TURN_REPLAY_MISMATCH")
        compared+=1; cohorts.append({"turn":offset+1,"arms":sorted(reached),"primary_input_sha256":next(iter(groups)),"cache_key_sha256":next(iter(entries))})
    return {"shared_turns_compared":compared,"cohorts":cohorts,"first_divergence":divergence}


@dataclass
class SpendGuard:
    hard_cap_usd: float
    rates_per_million: dict[str,float]
    reserved_usd: float = 0.0
    settled_usd: float = 0.0
    _reservations: dict[str,tuple[str,int,float]] = field(default_factory=dict)

    def reserve_before_call(self, call_id: str, model: str, maximum_total_tokens: int) -> float:
        if not call_id or call_id in self._reservations or model not in self.rates_per_million or maximum_total_tokens<0:
            raise ReplayContractError("SPEND_RESERVATION_INVALID")
        amount=maximum_total_tokens*self.rates_per_million[model]/1_000_000
        if self.settled_usd+self.reserved_usd+amount>self.hard_cap_usd:
            raise ReplayContractError("HARD_SPEND_CAP_PRECALL_STOP")
        self._reservations[call_id]=(model,maximum_total_tokens,amount); self.reserved_usd+=amount
        return amount

    def settle(self, call_id: str, actual_total_tokens: int) -> float:
        if call_id not in self._reservations or actual_total_tokens<0:
            raise ReplayContractError("SPEND_SETTLEMENT_INVALID")
        model,maximum,reserved=self._reservations.pop(call_id)
        if actual_total_tokens>maximum:
            raise ReplayContractError("PROVIDER_TOKENS_EXCEED_RESERVATION")
        actual=actual_total_tokens*self.rates_per_million[model]/1_000_000
        self.reserved_usd-=reserved; self.settled_usd+=actual
        return actual
