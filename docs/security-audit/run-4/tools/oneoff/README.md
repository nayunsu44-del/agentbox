# 일회용 스크립트 (기록용)

Windows 이어받기 세션에서 부모가 장부·결과를 손으로 고칠 때 쓴 스크립트다. 다시 돌리지 않는다. 근거를 남기려고 지우지 않고 여기에 모았다.

| 파일 | 한 일 | 검토 메모 |
|---|---|---|
| `_fix.py` | `agents/h-policy/raw.txt`를 덮어써서 승인 결정 단위와 exec 단위의 결과를 부모가 써 넣었다. 그 뒤 장부 단위와 **순서대로** 짝지었다. | 원본 `raw.txt`는 남지 않았다. 순서 짝짓기 탓에 승인 카드 단위에 승인 결정 단위의 검사가 들어갔다. 검토 때 그 검사를 `h_prev.out` 근거로 바로잡았다(장부 `x_parent_note`). |
| `_fix_card_unit.py` | 승인 카드 단위를 손으로 `candidate`로 바꾸고 F5 지문을 달았다. | 위와 같은 단위. |
| `fix_ids.py`, `remap_ids.py` | 부모가 옮겨 적은 헌터 결과의 coverage_id를 장부 순서로 다시 붙였다. | 옮겨 적기 편차의 근거. |
| `_patch_fence.py` | `gen3.py`·`gen5.py`에 `fence` 정의를 넣었다. | 도구 수정. |
| `_final_meta.py` | `run-metadata.json`의 최종 상태를 썼다. | `run_status: "complete_with_deferred_units"`는 스킬에 없는 값이다. 검토 뒤 다시 썼다. |
