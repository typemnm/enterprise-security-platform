# 서비스별 HOTL/HITL 운영 정책

Terraform 설치 후 외부 `terraform output -json deployment` 파일을 `--deployment-outputs`로 전달해 발견하거나 관리자 대시보드에서 등록된 `service_id`를 확인합니다. 이 CLI는 서비스 ARN, IPSet, 계정, 격리 대상, 로그 목적지 등의 입력을 받지 않습니다. 이미 등록된 활성 서비스의 정책만 변경합니다. 설치·조회 명령은 [빠른 설치](docs/quickstart.md), 회사 설정과 Slack은 [구성](docs/configuration.md), enforce 전 IAM 인수는 [보안 경계](docs/security-boundaries.md)를 따릅니다.

이 선택 운영 CLI의 사용자는 AWS CLI v2와 릴리스의 Python 의존성을 준비합니다. 기본 Terraform 설치에는 Python이 필요하지 않습니다. 정책 CLI의 `--plan`은 표준 Python만으로 실행되며 AWS 연결이 필요 없습니다. `--apply`는 pinned boto3 자료형을 사용하므로 `tests/requirements.txt`의 의존성이 필요합니다. 운영 프로필에는 실제 배포 리소스의 소유권·설정 조회와 해당 등록부의 `dynamodb:GetItem`/`dynamodb:UpdateItem` 권한이 있어야 합니다. legacy CFN 경로는 해당 foundation의 `cloudformation:DescribeStacks`도 필요합니다.

아래 파일을 저장소 밖 회사 설정 디렉터리의 `service-policy.json`으로 저장하고 `service_id`를 실제 발견된 값으로 바꿉니다. 자동 차단과 승인 후 수동 차단을 모두 끄는 관찰 설정입니다. 회사의 실제 WAF 규칙을 확인하기 전까지 자동 정책은 비활성 상태로 둡니다. 정책·실제 CIDR·그룹과 적용 결과를 공개 저장소에 커밋하지 않습니다.

```json
{
  "service_id": "checkout-prod",
  "response_mode": "observe",
  "manual_block_enabled": false,
  "auto_block_policy": {"enabled": false},
  "protected_cidrs": []
}
```

저장소 루트에서 PowerShell로 계획을 확인합니다. 회사 설정 디렉터리는 [빠른 설치](docs/quickstart.md)의 외부 경로입니다.

```powershell
$CompanyConfigDirectory = Join-Path $env:USERPROFILE 'company-security'
$ServicePolicy = Join-Path $CompanyConfigDirectory 'service-policy.json'
$CompanyProfile = 'company'
$ControlRegion = 'ap-northeast-2'
$InstallationId = '<INSTALLATION_ID>'
$DeploymentOutputs = Join-Path $CompanyConfigDirectory 'deployment-outputs.json'
python .\service-onboarding\policy.py --plan --config $ServicePolicy
```

정책을 반영할 때 실제 설치 ID, AWS 프로필, control-plane 리전을 명시합니다.

```powershell
python .\service-onboarding\policy.py --apply --installation-id $InstallationId --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs --config $ServicePolicy
```

HITL 승인 후 실제 IP 차단을 허용하려면 서비스의 `response_mode=enforce`, `manual_block_enabled=true`와 Terraform 설치의 `default_dry_run=false`, `acknowledge_enforcement=true`를 검토해 적용해야 합니다. `observe` 서비스 또는 설치의 dry run에서 생성한 사건은 승인을 받아도 dry run으로 유지됩니다. 정책을 바꾼 뒤 생성된 새 사건에서 승인·결과를 인수합니다. 허용 행동, 회사 관리자 권한, 사건의 source IP 및 승인 commit 검증도 함께 적용됩니다. 신규 설치의 별도 수동 차단 endpoint는 비활성이므로 승인된 상태 머신 흐름을 사용합니다. legacy 설치기만 `--enable-enforcement`로 설치 허용을 설정합니다.

기존 차단 롤백은 관리자 정정 작업이므로 서비스가 `observe`로 돌아간 후에도 허용됩니다. UI 롤백은 사건에 연결된 영구 WAF IPSet의 해당 `/32` 또는 `/128`만 제거하며 다른 주소는 유지합니다. 관찰 모드로 전환하는 것만으로 기존 차단이 해제되지는 않습니다.

HOTL 자동 차단을 허용하려면 다음 필드를 회사 검토를 거쳐 입력합니다.

| 필드 | 필요한 값 |
|---|---|
| `response_mode` | `enforce` |
| `auto_block_policy.enabled` | `true` |
| `auto_block_policy.signal_types` | `["WAF_PATTERN"]` |
| `auto_block_policy.rule_ids` | 실제 로그에서 확인하고 검토한 정확한 규칙 ID 목록, 1~100개 |
| `auto_block_policy.window_seconds` | 60~3600초 |
| `auto_block_policy.min_requests` | 같은 서비스·IP·규칙·정책 revision에서 고유 요청 2~10000개 |

규칙 ID는 AWS WAF의 `terminatingRuleId`, `nonTerminatingMatchingRules[].ruleId` 및 rule group의 해당 rule ID에서 확인합니다. 실제 회사의 트래픽으로 오탐을 검토한 규칙만 선택합니다. 와일드카드, 임의 ARN, CloudTrail/GuardDuty 기반 자동 차단 정책은 이 CLI에서 지원하지 않습니다. 설치가 dry run이면 서비스 정책을 enforce로 바꾸어도 실제 자동 차단이 실행되지 않습니다. 외부 Terraform 변수의 `response_mode="enforce"`, `default_dry_run=false`, `acknowledge_enforcement=true`를 계획·적용한 후 서비스 정책을 아래 CLI로 반영하고 그 이후 새 사건의 결과를 확인합니다. 이미 등록된 서비스 정책은 주기적 발견에서 보존되므로 설치 변수만으로 개별 서비스 정책이 바뀌지는 않습니다.

명시한 자동 정책에 일치하는 요청은 임계치에 도달하기 전까지 사건을 만들지 않고 원본 CloudWatch WAF 로그의 관측으로 남습니다. 카운터는 재전송 및 겹치는 배치의 동일 provider event를 제외하고 서비스·IP·규칙·정책 revision별 고유 요청만 셉니다. 관측 시각을 기준으로 `window_seconds` 크기의 고정 구간(tumbling window)을 사용하므로, 두 구간에 걸친 요청 수는 합산하지 않습니다. 여러 검토된 규칙이 동시에 일치하면 규칙별로 카운터를 유지합니다. 임계치에 도달한 각 구간·IP·규칙·revision은 안정된 집계 ID로 사건 하나를 만들며, 이후 중복 전달과 재시도는 최초 예약한 요약과 증거를 그대로 사용합니다. 오래되거나 미래인 관측으로 새 자동 차단 증거를 만들지 않습니다.

사건 생성 한도는 관측 요청 수와 분리되어 서비스당 플랫폼 처리 시간의 한 시간에 기본 30건입니다. 서로 다른 과거 시간의 지연 로그도 같은 현재 시간 한도를 공유합니다. 임계치 전 정책 관측은 이 한도를 소비하지 않으며, 집계 사건 하나는 한 건을 소비합니다. 이미 예약된 발행 대기 사건은 한도를 다시 소비하지 않고 재전송합니다. 로그 일치 자체는 침투 성공의 증거가 아니며, 실제 차단 직전에 최신 정책 revision, 관측 신선도, 등록 서비스 범위 및 WAF 연결을 다시 검증합니다.

수집은 최대 99개 관측 claim을 포함하는 작은 트랜잭션 청크를 순차 확정하고, 해당 청크가 임계치에 도달하면 나머지 배치 처리를 기다리지 않고 집계 사건을 발행합니다. 이후 청크의 오류나 시간 초과가 이미 확정한 카운터·발행 대기 예약·발행된 사건을 되돌리지 않습니다. CloudWatch 재전송은 저장된 claim과 최초 publication을 대조하여 중복 증가나 새 집계 ID를 방지합니다. 대량 로그의 수집 실패는 전용 DLQ와 운영 경보에서 확인합니다.

`awslogs` 모양이나 같은 계정의 `InvokeFunction` 호출 자체는 출처 증거가 아닙니다. 수집기는 등록된 정확한 로그 그룹·스트림의 저장 이벤트를 `FilterLogEvents`로 읽고 event ID, 시각 및 원문 SHA256이 일치한 기록만 셉니다. 검증 카운터에는 `source_validation_version=STORED_CLOUDWATCH_V1`, IP 및 최신 검증 관측 시각을 저장합니다. 이전 버전의 출처 미검증 카운터와 새 관측을 합치지 않으며, 해당 구간은 검토 상태로 중단하고 다음 새 시간 구간부터 검증된 카운터를 생성합니다. 준비 함수와 실제 대응 함수는 카운터를 강하게 읽어 재확인합니다. 임계치 숫자와 집계 hash만 위조한 입력은 자동 실행을 허용하지 않습니다.

CloudWatch 저장 검증은 로그 작성자의 신뢰를 대신하지 않습니다. 회사의 수집 로그 그룹에 `PutLogEvents`를 할 수 있는 IAM 역할은 WAF 로그 전달과 검토된 운영자 등 신뢰하는 작성자만 허용해야 합니다. 일반 업무 역할·사용자가 그 그룹에 보안 로그를 쓰지 못하도록 회사 IAM 정책을 확인합니다. 합성 인수 검증의 운영자는 별도 fixture 로그 그룹에만 시험 기록을 쓰며, 그 결과는 실제 WAF 탐지나 업무 트래픽의 증거로 취급하지 않습니다.

최종 처리 리포트는 호출자가 전달한 `response`, `mode` 또는 성공 문자열을 근거로 생성하지 않습니다. 저장된 workflow 실행, Tier·dry run, 최초 승인 결정·callback commit을 대조하고, 실제 차단 사실은 그 실행의 대응 기록 테이블에서 읽습니다. 기록이 없거나 결과가 불명확하면 성공으로 표시하지 않습니다. terminal EventBridge 경로도 `DescribeExecution`의 실제 종료 상태를 확인하며 execution input/output/Cause는 읽지 않습니다. 승인 RPC의 직접 Lambda 호출 권한은 인증된 Cognito 사용자를 검증하는 대시보드 역할과 신뢰하는 플랫폼 배포 운영자에게만 부여합니다.

`enforce` 설정은 추가 플래그가 필요합니다.

```powershell
python .\service-onboarding\policy.py --apply --enable-enforcement --installation-id $InstallationId --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs --config $ServicePolicy
```

`protected_cidrs`에는 차단에서 제외할 정렬된 IPv4/IPv6 네트워크를 넣습니다. 예를 들어 `10.0.0.0/8`, `2001:db8::/48`처럼 네트워크 주소와 prefix를 정확히 입력해야 합니다. 호스트 비트가 포함된 `10.0.0.1/24`는 거절됩니다. 회사 관리망·중요 외부 파트너 대역은 회사가 확인한 실제 값으로 설정합니다.

선택 필드 `allowed_admin_groups`와 `allowed_reader_groups`는 실제 회사 Cognito 그룹 이름을 받습니다. 생략하면 기존 그룹을 보존합니다. `allowed_actions`를 제공하면 `monitor`/`block_ip` 중 기존 서비스와 foundation `AllowedActions` 양쪽이 허용하는 행동만 선택할 수 있습니다. 이 CLI로 행동 범위를 넓힐 수 없으며, 범위를 줄인 뒤 확대하려면 별도의 검토된 서비스 재등록/설치 변경이 필요합니다.

반영은 현재 계정과 foundation 소유 태그를 확인하고 등록부를 강하게 읽은 뒤 기존 `revision`, 계정, 활성 상태를 조건으로 수행됩니다. `REVIEW_REQUIRED/REGISTRY_CHANGED`는 다른 변경이 먼저 완료됐다는 뜻입니다. 최신 상태를 확인하고 새 계획을 검토합니다. 실패한 CAS를 새 revision으로 덮어쓰지 않습니다. 응답이 유실됐을 때는 한 번의 strong read로 반영 여부만 확인하고 불명확하면 검토 상태로 종료합니다.

정책 변경은 공통 SHA256 revision을 갱신합니다. 이전 revision에 묶인 승인 대기 사건은 자동/수동 조치를 다시 허용하지 않으며, 새로 생성된 사건을 다시 검토해야 합니다. 같은 정책을 재적용하면 `UNCHANGED`로 끝납니다. `observe`, `manual_block_enabled=false`, `auto_block_policy.enabled=false`로 다시 적용하면 새 대응을 중지합니다. 이미 차단된 IP의 해제는 대시보드 롤백으로 별도 수행합니다.
