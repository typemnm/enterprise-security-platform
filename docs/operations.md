# 운영과 인수

명령은 저장소 루트에서 실행하며 `$CompanyConfig`, `$CompanyProfile`, `$ControlRegion`은 [빠른 설치](quickstart.md)에서 정한 회사 값입니다. 배포 결과·보고서·검증 파일은 회사 내부에 보관합니다.

## 운영 전 확인

- 발견 후보와 제외 태그·공유 ACL·기존 규칙·로그 전달을 확인합니다. 단순 attach와 수집→사건→대응→알림 연결을 구분합니다.
- Cognito 관리자 최초 로그인·비밀번호 변경·MFA·그룹 권한, 비로그인·다른 서비스 요청 거절을 확인합니다.
- 회사 Slack의 초기 요약·최종 결정/성공/실패/dry run, 중복 갱신과 발송 실패 경보를 확인합니다.
- [회사 writer IAM 경계](security-boundaries.md), 오리진 우회와 forwarded IP 의미, 관리망·중요 파트너 보호 CIDR을 확인합니다.
- observe에서 오탐·부하·비용을 검토한 뒤 전용 시험 서비스에만 실제 차단·HITL 승인/반려·롤백·동시 갱신을 인수합니다.

## 지원 대상 조회와 재조정

```powershell
python .\service-onboarding\onboard.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --discover
python .\service-onboarding\onboard.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --discover --apply --confirm-installation-id '<INSTALLATION_ID>'
```

두 번째 명령은 실제 WAF 조정을 수행합니다. placeholder를 외부 파일의 실제 설치 ID로 바꿉니다. `all-supported` 설치에는 `--allow-all-supported`도 필요합니다. `REVIEW_REQUIRED`는 로그 목적지·공유 소유·정책을 검토한 후 해결하며 기존 설정을 임의로 초기화하지 않습니다.

## 관찰에서 실제 대응으로 전환

외부 설치 JSON의 `response_mode=enforce`와 설치 명령의 `--enable-enforcement`를 검토합니다. 이미 등록된 서비스 정책은 발견에서 보존되므로 설치 JSON만 바꿔도 개별 서비스가 자동으로 enforce가 되지 않습니다. [서비스 정책](../SERVICE_POLICY.md)으로 등록된 서비스의 수동/자동 정책·규칙 ID·임계치·보호 CIDR을 설정합니다.

observe 또는 설치 dry run에서 생성한 사건은 승인을 받아도 모의 실행을 유지합니다. 정책 전환 이후 새 사건으로 실제 결과를 인수합니다. 다시 observe/자동 정책 비활성/수동 차단 비활성으로 설정하면 새 대응을 중단하지만 기존 차단은 해제되지 않습니다.

## 차단 롤백

Cognito 관리자가 HOTL 사건을 열고 차단 롤백 버튼을 사용합니다. 서버는 사건에 연결된 영구 IPSet과 정확한 `/32` 또는 `/128`을 조회하고 최신 LockToken으로 해당 주소만 제거합니다. 현재 목록·다른 주소·Description·작업 영수증과 감사 결과를 확인합니다. 브라우저가 IPSet ARN·해제 IP·계정을 지정하는 흐름은 지원하지 않습니다.

관찰 모드에서도 기존 차단 정정은 가능합니다. 수동으로 IPSet 목록을 덮어쓰거나 보존 tombstone을 삭제해 같은 사건을 재실행하지 않습니다. 감사 실패·WAF 충돌·미확인 결과가 있으면 현재 목록과 기록을 먼저 확인합니다.

## 합성 검증 도구

자동 연결·실제 차단·Slack·관리자 초대가 비활성인 **별도 검증 설치**에서만 아래 도구의 guard를 충족할 수 있습니다.

```powershell
python .\validate_http.py --profile $CompanyProfile --region $ControlRegion
python .\validate_cloud.py --execute --profile $CompanyProfile --region $ControlRegion
python .\validate_receipts.py --execute --profile $CompanyProfile --region $ControlRegion
python .\validate_operations.py --execute --profile $CompanyProfile --region $ControlRegion --source-region us-east-1 --timeout 360
```

각 도구의 `--help`로 설치 결과 경로·시간 예산을 확인합니다. 기본 결과 파일은 `build/`에 남습니다. HTTP는 인증 경계, cloud는 소유 fixture 로그·고유 관측·사건/승인/모의 결과, receipts는 이번 사건 결과의 실제 CMK 큐 도착을 검증합니다. 운영 도구는 소유한 지역 알람만 일시 ALARM으로 바꾸고 복원하며 집계 EventBridge→SNS 전달 지표를 확인합니다. 실제 회사 Slack 수신·업무 차단 인수는 별도입니다.

## 장애와 알림

로그 수집 Lambda는 300초 제한, 입력 4MiB·10,000개 수용 한도를 사용합니다. 이는 10,000개 전량의 시간·성공 보장이 아닙니다. 리전 간 왕복·throttling·재시도를 고려해 실제 소규모 부하 시험 후 규모를 늘립니다. 사건 생성은 서비스당 시간당 기본 30건이며 고유 관측 건수와 분리합니다.

Lambda 비동기 수집은 최대 두 번 재시도하고 1시간의 이벤트 수명을 적용합니다. 실패는 같은 리전의 전용 private SQS 목적지에 보관합니다. `Errors`, `AsyncEventsDropped`, `DestinationDeliveryFailures`, 큐 depth를 확인합니다. 큰 입력의 실패 기록은 SQS/비동기 메시지 한도로 전달되지 않을 수 있으므로 경보와 원본 로그를 함께 확인합니다.

EventBridge 대상·DLQ는 호환되는 CMK와 정확한 service/key 권한을 사용합니다. 지역 릴레이는 설치의 정확한 네 알람 이름만 중앙으로 보내며, Event bus 대상에는 사용자 지정 RetryPolicy를 넣지 않습니다. 중앙 SNS 게시 내용은 AlarmName/NewStateValue입니다. 알림 비활성 설치에서는 Slack 전달이 이뤄지지 않으므로 회사 운영에서는 실제 수신 가능한 채널을 인수합니다.

DLQ를 장애 함수에 자동 연결해 무조건 재실행하지 않습니다. 원인 해결 후 Lambda requestPayload와 EventBridge 원본을 구분하고 계정·서비스·원본 로그·정책을 확인해 원래 경로로 재전달합니다. claim·발행 revision·영구 영수증을 보존해 중복을 막습니다. 실패 큐 전달 자체가 실패한 경보와 지역 릴레이 장애도 지역 콘솔에서 확인합니다.

## 업데이트·백업·해제

검토한 릴리스로 다시 빌드하고 같은 설치 ID·외부 설정을 사용합니다. Slack 인자·`--allow-all-supported`·실행 허용 등 유지할 설정을 명시합니다. 설치 도구는 해시·버전·소유 범위를 검사하고 데이터·큐·Cognito 등의 삭제/교체를 자동 허용하지 않습니다. `DESTRUCTIVE_CHANGESET_REVIEW_REQUIRED`는 실제 change set을 검토할 사유이며 guard를 우회하지 않습니다.

DynamoDB PITR·삭제 보호, S3 버전·KMS·Retain과 로그 보존을 확인합니다. 세션/리스의 TTL 삭제는 비동기이며 응답·발행 영수증은 TTL로 지우지 않습니다. 오래된 Lambda 버전·아티팩트·Retain 자산의 비용과 정리도 회사가 검토합니다. 복원은 업무 서비스의 현재 WAF 설정·등록 revision·작업 영수증과 대조하고 실제 복구를 연습합니다.

서비스 해제와 플랫폼 제거는 별도 변경 작업입니다. 등록 비활성화·감사 export·해당 namespace 규칙의 검토된 제거·Retain 자산 보존 순서로 수행합니다. 설치 이름 변경·태그 해제·관찰 모드 전환을 삭제 명령으로 사용하지 않습니다.
