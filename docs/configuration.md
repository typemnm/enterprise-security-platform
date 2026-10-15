# 회사 구성

회사 설정은 저장소 밖 JSON 파일과 AWS 프로필, CLI 인자, Secrets Manager로 분리합니다. 공개 저장소에는 예제·schema·코드만 둡니다. 계정 번호·실제 ARN·관리자 이메일·Slack ID·대시보드 URL·보고서·배포 결과를 공개 커밋하지 않습니다.

## 설치 파일

`service-onboarding/installation.example.json`을 외부 경로로 복사합니다. 아래 예제에는 실제 계정이나 업무 서비스 ARN이 없습니다.

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

4. Token 값 대신 Secret의 전체 ARN과 채널 ID만 설치 인자로 전달합니다. 아래 변수의 placeholder를 회사 값으로 교체하고, 기록·공개 커밋에 남기지 않습니다.

```powershell
$SlackSecretArn = '<SECRET_ARN>'
$SlackChannelId = '<CHANNEL_ID>'
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --plan --slack-secret-arn $SlackSecretArn --slack-channel-id $SlackChannelId
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --apply --slack-secret-arn $SlackSecretArn --slack-channel-id $SlackChannelId
```

이 적용은 검증 전용 모드가 아니므로 자동 발견·WAF 재조정이 실행될 수 있습니다. 설치 파일에 맞는 `--allow-all-supported`·검토한 `--enable-enforcement`·선택 관리자 인자를 함께 유지합니다. 갱신에서 Slack 인자를 생략하면 알림을 비활성화합니다.

`aws/secretsmanager` 기본 키와 같은 계정·리전의 활성 대칭 customer managed key를 지원합니다. 설치 프로필은 DescribeSecret과 해당 회사 키의 DescribeKey가 필요하며, 값 조회 없이 정확한 키 ARN을 확인합니다. 회사 키 정책은 notifier·운영 알림 역할의 확인된 Secrets Manager 경유 복호화 권한을 허용해야 합니다. Token 회전 후 회사의 새 사건으로 초기 요약·결정 결과·중복 갱신·실패 경보를 확인합니다.

Slack 알림은 보고서 요약과 추천뿐 아니라 **결정된 행동·실제 결과**를 표시합니다. 메시지 도착은 WAF 차단 성공의 증거가 아닙니다. 사용자 승인·반려·롤백은 Cognito로 로그인한 대시보드에서 수행합니다.

## 관리자·모델·서비스 정책

관리자 이메일은 `--admin-email`로 운영자가 명시할 때만 Cognito 초대를 요청합니다. 기본 이메일·비밀번호·채널은 없습니다. 초대된 관리자는 비밀번호 변경과 소프트웨어 토큰 MFA를 등록합니다. pool/client/callback/session은 foundation이 연결하며, 고객 URL·세션·Cognito 설정을 공개 저장소에 넣지 않습니다.

선택 `--model-arn`은 회사가 사용할 수 있는 같은 control 리전의 Bedrock 모델·inference profile을 사용합니다. 모델 없이도 수동 검토가 가능하며 AI 추천은 대응 권한을 생성하지 않습니다. 별도 외부 AI vendor secret은 기본 요구사항이 아닙니다.

관찰·수동 차단 허용·자동 차단 임계치·보호 CIDR·읽기/관리 그룹은 [서비스 정책 CLI](../SERVICE_POLICY.md)로 등록된 서비스에만 적용합니다. 정책 파일도 외부에 보관합니다. 실제 대응에는 회사 IAM 인수, 서비스 enforce, 설치의 `--enable-enforcement`, 해당 정책 이후 생성한 사건과 현재 증거·승인 검증이 모두 필요합니다.
