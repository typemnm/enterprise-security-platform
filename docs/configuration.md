# 회사 구성

기본 Terraform 배포의 회사 설정은 저장소 밖 tfvars·backend 파일, AWS credential chain과 Secrets Manager로 분리합니다. 공개 저장소에는 예제·schema·코드와 provider 잠금 파일만 둡니다. 계정 번호·실제 ARN·관리자 이메일·Slack ID·대시보드 URL·보고서·배포 결과를 공개 커밋하지 않습니다.

## Terraform 입력과 state

`terraform/variables.tf`의 입력 계약과 [빠른 설치](quickstart.md)의 외부 tfvars 예제를 사용합니다.

| 입력 | 계약 |
|---|---|
| `installation_id`, `environment`, `account_id`, `control_region` | 설치 신원과 계정·리전 guard. 기존 설치의 ID를 유지 |
| `discovery_regions`, `installation_scope`, `exclude_tags` | 기본 태그 선택·제외 정책. CloudFront 수집은 `us-east-1` 포함. all-supported는 `acknowledge_all_supported=true` 필요 |
| `response_mode`, `allowed_actions`, `principal_scopes` | 기본 observe, 허용 행동 범위, 현재 principal adapter는 빈 목록 |
| `automatic_onboarding_enabled` | 기본 false. 플랫폼 인수 후 명시적으로 true로 전환 |
| `default_dry_run`, `acknowledge_enforcement` | 기본 true·false. 실제 대응 설정은 명시 acknowledgement와 개별 서비스 정책도 필요 |
| `runtime_zip_path`, `dashboard_zip_path`, `release_id` | 같은 검증 릴리스의 ZIP 경로와 manifest ID. 기본 ZIP 경로는 `../build/release/` |
| `artifact_key_prefix` | 기본 `packages`. 버전 관리되는 S3의 안정된 object key prefix. 기존 설치 이관 시 현재 prefix를 보존 |
| `slack_secret_arn`, `slack_channel_id`, `slack_secret_key_arn` | 기본 비활성. Secret 값 대신 같은 계정·control 리전의 ARN과 필요한 정확한 KMS 키 ARN |
| `model_arn`, `enable_nacl_response` | 기본 미설정·비활성. 회사의 별도 검토 필요 |

회사 tfvars, backend 설정, state·backup, 저장 계획·plan JSON, 배포 출력과 Terraform 캐시는 공개 저장소·ZIP에 넣지 않습니다. `TF_DATA_DIR`도 회사 외부 경로로 둡니다. provider `.terraform.lock.hcl`은 검토된 소스이므로 커밋합니다. provider 업그레이드는 새 계획·시험과 lock checksum 검토를 거칩니다.

기본 backend는 회사의 암호화된 S3입니다. 설치/계정/환경마다 key를 분리하고 버전 관리·잠금(`use_lockfile=true`)·TLS·최소 권한·KMS·복구 절차를 확인합니다. backend의 자격증명은 파일이 아닌 회사 AWS credential chain을 사용합니다. backend 변경 시 state 이관을 별도 변경 작업으로 검토합니다. `sensitive` 출력도 state/plan에는 값이 남을 수 있으므로 접근을 제한합니다.

실제 Secret 값·비밀번호를 Terraform 변수·리소스·data source에 넣지 않습니다. 특히 `aws_secretsmanager_secret_version`으로 Slack token을 읽으면 state에 들어갈 수 있습니다. notifier와 운영 함수가 실행 시 Secrets Manager에서 읽도록 ARN만 전달합니다.

아티팩트는 기본 `packages/runtime.zip`, `packages/dashboard.zip`의 안정된 S3 key에 저장합니다. 내용 변경은 버전 관리되는 새 S3 object version을 만들며, Lambda는 해당 `S3ObjectVersion`에 고정됩니다. Lambda 배포 버전과 alias도 확인해 최신 key 조회에 따라 실행 코드가 바뀌지 않도록 합니다. `release_id`는 manifest와 대응하는 메타데이터이며 key 이름을 릴리스마다 바꿀 필요는 없습니다. 이관에서는 실제 사용 중인 key prefix·버전·코드 hash를 먼저 대조해 보존하고, prefix 변경을 코드 교체와 분리해 계획합니다.

Cognito browser client는 `generate_secret=false`로 생성합니다. 기존 client를 import할 때 API가 이 false 값을 반환하지 않는 차이에 한해 해당 immutable 필드만 `ignore_changes`로 유지합니다. 기존 client에 `ClientSecret`이 없다는 읽기 전용 preflight가 필요하며, 비밀 client로 전환하거나 client를 교체하는 방식으로 이 차이를 해결하지 않습니다. import 임시 작업용 `ignore_changes=all`은 공개 기본 구성에 허용하지 않습니다.

`principal_scopes`는 빈 목록만 허용합니다. 제외 태그 JSON은 UTF-8 1,536바이트, 각 Lambda 환경은 UTF-8 4,096바이트 예산을 확인하며 초과 입력은 적용 전에 중단합니다.

## 운영 CLI와 legacy 설치 파일

선택 Python 운영 CLI 또는 legacy 설치기를 사용하는 경우 `service-onboarding/installation.example.json`을 외부 경로로 복사합니다. Terraform 설치의 tfvars와 scope·region·mode를 일치시킵니다. 아래 예제에는 실제 계정이나 업무 서비스 ARN이 없습니다.

```json
{
  "schema_version": "1.0",
  "installation_id": "company-security-prod",
  "environment": "prod",
  "discovery": {
    "scope": "tagged",
    "regions": ["ap-northeast-2", "us-east-1"],
    "exclude_tags": {"security:exclude": "true"}
  },
  "response_mode": "observe",
  "allowed_actions": ["monitor", "block_ip"],
  "principal_scopes": []
}
```

| 필드 | 계약 |
|---|---|
| `installation_id` | 계정 안에서 관리하는 설치 이름. 소문자로 시작하는 3~31자 영문·숫자·하이픈. 갱신 시 유지 |
| `environment` | 회사가 선택하는 환경 태그 |
| `account_id` | 선택 계정 guard. 실제 값은 외부 파일에만 저장. 생략하면 STS 계정 확인 |
| `discovery.scope` | 기본 `tagged`. `all-supported`는 명시 opt-in과 CLI `--allow-all-supported`가 필요 |
| `discovery.regions` | 공개 ALB를 발견할 활성 리전. 제어 리전과 CloudFront용 `us-east-1`도 설치에 포함 |
| `discovery.exclude_tags` | 대상에서 제외할 태그. `security:managed=false`·제어 영역 태그도 제외 |
| `response_mode` | 기본 `observe`. 초기 등록 기본값이며 이미 등록된 서비스의 운영 정책을 덮어쓰지 않음 |
| `allowed_actions` | `monitor`·`block_ip`의 설치 허용 범위. 이 목록만으로 실제 차단 활성화되지 않음 |
| `principal_scopes` | 현재 `[]`만 지원. CloudTrail principal adapter가 없으므로 다른 값은 거절 |
| `dashboard_origin` | 선택적으로 검증한 custom HTTPS origin. 미지정이면 HTTP API HTTPS URL 자동 제공. DNS/custom domain 설정을 대신하지 않음 |

schema의 리전 최대 개수 안에 있어도 알람 목록 파라미터와 Lambda 환경의 4KiB 예산을 초과하면 설치 도구가 중단합니다. 리전 수와 제외 설정을 줄여 다시 계획합니다. 비용과 계정별 quota는 회사가 확인합니다.

## 서비스 선택 태그

```text
security:managed = true
security:service-id = company-customer-api
```

ID 태그는 선택 사항이며 생략하면 안정적인 ID를 생성합니다. ID는 소문자로 시작하는 3~48자 영문·숫자·하이픈입니다. 현재 하나의 ID는 하나의 보호 리소스에 연결합니다. 앞단 CloudFront와 뒤 ALB를 각각 관리하려면 다른 ID와 보호 정책을 검토합니다. 제외할 대상에는 `security:exclude=true` 또는 `security:managed=false`를 사용합니다.

## Slack 연결

1. 회사 Slack workspace에서 App을 만들고 Bot OAuth scope `chat:write`를 추가해 설치합니다.
2. 알림 채널에 봇을 추가하고 채널 ID를 확인합니다. 비공개 채널에는 봇을 명시적으로 초대합니다.
3. Bot User OAuth Token을 회사 계정의 **control-plane과 같은 리전** Secrets Manager에 다음 JSON 형식으로 저장합니다. 평문 Token만 넣으면 notifier가 거절합니다.

```json
{"bot_token":"<BOT_TOKEN>"}
```

4. Token 값 대신 Secret의 전체 ARN과 채널 ID만 외부 tfvars에 전달하고 새 Terraform plan을 검토해 적용합니다.

```hcl
slack_secret_arn     = "<SECRET_ARN>"
slack_channel_id     = "<CHANNEL_ID>"
# 고객 관리 키를 쓰는 Secret만 정확한 키 ARN을 지정합니다.
slack_secret_key_arn = "<CUSTOMER_KMS_KEY_ARN_OR_EMPTY>"
```

자동 연결 상태와 실제 대응 허용도 외부 tfvars에서 함께 검토합니다. 검증 설치에는 Slack을 설정하지 않습니다. tfvars에서 기존 Slack 값을 지우면 알림이 비활성화됩니다. 실제 Token은 이 파일에도 저장하지 않습니다.

`aws/secretsmanager` 기본 키와 같은 계정·리전의 활성 대칭 customer managed key를 지원합니다. 회사 운영자는 DescribeSecret·DescribeKey의 메타데이터로 실제 키를 확인해 ARN을 지정하며 Token 값은 읽거나 계획에 출력하지 않습니다. 회사 키 정책은 notifier·운영 알림 역할의 확인된 Secrets Manager 경유 복호화 권한을 허용해야 합니다. Token 회전 후 회사의 새 사건으로 초기 요약·결정 결과·중복 갱신·실패 경보를 확인합니다.

Slack 알림은 보고서 요약과 추천뿐 아니라 **결정된 행동·실제 결과**를 표시합니다. 메시지 도착은 WAF 차단 성공의 증거가 아닙니다. 사용자 승인·반려·롤백은 Cognito로 로그인한 대시보드에서 수행합니다.

## 관리자·모델·서비스 정책

Terraform은 기본 관리자나 비밀번호를 만들지 않습니다. 회사가 명시적으로 선택한 담당자를 배포된 Cognito pool에 별도 초대하고 `AdminGroupName` 출력의 그룹에 추가합니다. 임시 비밀번호를 tfvars/state에 넣지 않습니다. 초대된 관리자는 비밀번호 변경과 소프트웨어 토큰 MFA를 등록합니다. pool/client/callback/session은 foundation이 연결하며 회사 URL·세션·Cognito 설정은 비공개입니다. legacy Python 설치기만 `--admin-email` 인자를 지원합니다.

담당자와 주소를 회사가 확인한 경우에만 아래 명령으로 실제 이메일 초대를 요청합니다. 이 명령은 Terraform apply와 별개이며 비밀번호를 CLI에 입력하지 않습니다. 출력·명령 이력에도 회사 이메일이 남을 수 있으므로 회사 전용 터미널에서 실행합니다.

```powershell
$Deployment = Get-Content -LiteralPath $DeploymentOutputs -Raw | ConvertFrom-Json
$UserPoolId = $Deployment.outputs.CognitoUserPoolId
$AdminGroup = $Deployment.outputs.AdminGroupName
$AdminEmail = '<ADMIN_EMAIL>'
aws cognito-idp admin-create-user --user-pool-id $UserPoolId --username $AdminEmail --desired-delivery-mediums EMAIL --user-attributes "Name=email,Value=$AdminEmail" 'Name=email_verified,Value=true' --profile $env:AWS_PROFILE --region $ControlRegion --no-cli-pager
aws cognito-idp admin-add-user-to-group --user-pool-id $UserPoolId --username $AdminEmail --group-name $AdminGroup --profile $env:AWS_PROFILE --region $ControlRegion --no-cli-pager
```

이미 존재하는 사용자라면 새로 생성하거나 다른 계정을 덮어쓰지 않고 정확한 사용자·검증된 이메일과 회사 역할을 확인한 뒤 그룹 변경을 검토합니다. 최초 로그인·MFA·서비스별 권한 검증은 사람이 수행해야 합니다.

선택 `model_arn`은 회사가 사용할 수 있는 같은 control 리전의 Bedrock 모델·inference profile을 사용합니다. 모델 없이도 수동 검토가 가능하며 AI 추천은 대응 권한을 생성하지 않습니다. 별도 외부 AI vendor secret은 기본 요구사항이 아닙니다.

관찰·수동 차단 허용·자동 차단 임계치·보호 CIDR·읽기/관리 그룹은 [서비스 정책 CLI](../SERVICE_POLICY.md)로 등록된 서비스에만 적용합니다. 정책 파일도 외부에 보관합니다. 실제 대응에는 회사 IAM 인수, 서비스 enforce, 설치의 `default_dry_run=false`, 해당 정책 이후 생성한 사건과 현재 증거·승인 검증이 모두 필요합니다.
