# 운영과 인수

명령은 제품 루트에서 실행하며 [빠른 설치](quickstart.md)의 외부 `$CompanyDirectory`·`$DeploymentOutputs`를 사용합니다. Terraform 배포에는 Python이 필요하지 않습니다. 아래 운영·검증 CLI를 선택하면 Python과 `tests/requirements.txt` 의존성을 별도로 준비합니다. 배포 출력·보고서·검증 파일은 회사 내부에 보관합니다.

```powershell
$CompanyProfile = $env:AWS_PROFILE
$ControlRegion = 'ap-northeast-2'
$CompanyConfig = Join-Path $CompanyDirectory 'installation.json'
if (-not (Test-Path -LiteralPath $CompanyConfig)) {
    Copy-Item -LiteralPath .\service-onboarding\installation.example.json -Destination $CompanyConfig
}
python -m pip install -r .\tests\requirements.txt
```

외부 installation JSON은 Terraform tfvars와 같은 설치 ID·환경·리전·scope·mode를 지정합니다. 기존 파일이 있다면 복사로 덮어쓰지 않고 검토합니다. 출력 파일은 `terraform output -json deployment`로 다시 생성하며, 도구는 STS·설치 태그·실제 AWS 리소스와 교차 검증합니다. 파일 내용만으로 권한을 부여하지 않습니다.

## 운영 전 확인

- 발견 후보와 제외 태그·공유 ACL·기존 규칙·로그 전달을 확인합니다. 단순 attach와 수집→사건→대응→알림 연결을 구분합니다.
- Cognito 관리자 최초 로그인·비밀번호 변경·MFA·그룹 권한, 비로그인·다른 서비스 요청 거절을 확인합니다.
- 회사 Slack의 초기 요약·최종 결정/성공/실패/dry run, 중복 갱신과 발송 실패 경보를 확인합니다.
- [회사 writer IAM 경계](security-boundaries.md), 오리진 우회와 forwarded IP 의미, 관리망·중요 파트너 보호 CIDR을 확인합니다.
- observe에서 오탐·부하·비용을 검토한 뒤 전용 시험 서비스에만 실제 차단·HITL 승인/반려·롤백·동시 갱신을 인수합니다.

## 지원 대상 조회와 재조정

```powershell
python .\service-onboarding\onboard.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs --discover
python .\service-onboarding\onboard.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs --discover --apply --confirm-installation-id '<INSTALLATION_ID>'
```

두 번째 명령은 실제 WAF 조정을 수행합니다. placeholder를 외부 파일의 실제 설치 ID로 바꿉니다. `all-supported` 설치에는 `--allow-all-supported`도 필요합니다. `REVIEW_REQUIRED`는 로그 목적지·공유 소유·정책을 검토한 후 해결하며 기존 설정을 임의로 초기화하지 않습니다.

## 관찰에서 실제 대응으로 전환

외부 Terraform tfvars의 `response_mode="enforce"`, `default_dry_run=false`, `acknowledge_enforcement=true`를 새 계획으로 검토합니다. 이미 등록된 서비스 정책은 발견에서 보존되므로 설치 변수만 바꿔도 개별 서비스가 자동으로 enforce가 되지 않습니다. [서비스 정책](../SERVICE_POLICY.md) CLI에 `--deployment-outputs $DeploymentOutputs`를 전달해 등록된 서비스의 수동/자동 정책·규칙 ID·임계치·보호 CIDR을 설정합니다.

observe 또는 설치 dry run에서 생성한 사건은 승인을 받아도 모의 실행을 유지합니다. 정책 전환 이후 새 사건으로 실제 결과를 인수합니다. 다시 observe/자동 정책 비활성/수동 차단 비활성으로 설정하면 새 대응을 중단하지만 기존 차단은 해제되지 않습니다.

## 차단 롤백

Cognito 관리자가 HOTL 사건을 열고 차단 롤백 버튼을 사용합니다. 서버는 사건에 연결된 영구 IPSet과 정확한 `/32` 또는 `/128`을 조회하고 최신 LockToken으로 해당 주소만 제거합니다. 현재 목록·다른 주소·Description·작업 영수증과 감사 결과를 확인합니다. 브라우저가 IPSet ARN·해제 IP·계정을 지정하는 흐름은 지원하지 않습니다.

관찰 모드에서도 기존 차단 정정은 가능합니다. 수동으로 IPSet 목록을 덮어쓰거나 보존 tombstone을 삭제해 같은 사건을 재실행하지 않습니다. 감사 실패·WAF 충돌·미확인 결과가 있으면 현재 목록과 기록을 먼저 확인합니다.

## 합성 검증 도구

자동 연결·실제 차단·Slack·관리자 초대가 비활성인 **별도 검증 설치**에서만 아래 도구의 guard를 충족할 수 있습니다.

```powershell
python .\validate_http.py --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs
python .\validate_cloud.py --execute --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs
python .\validate_receipts.py --execute --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs
python .\validate_operations.py --execute --profile $CompanyProfile --region $ControlRegion --deployment-outputs $DeploymentOutputs --source-region us-east-1 --timeout 360
```

각 도구의 `--help`로 결과 경로·시간 예산을 확인합니다. 기본 검증 파일은 private `build/`에 남으며 공개 배포 ZIP에는 포함하지 않습니다. HTTP는 인증 경계, cloud는 소유 fixture 로그·고유 관측·사건/승인/모의 결과, receipts는 이번 사건 결과의 실제 CMK 큐 도착을 검증합니다. 운영 도구는 소유한 지역 알람만 일시 ALARM으로 바꾸고 복원하며 집계 EventBridge→SNS 전달 지표를 확인합니다. 실제 회사 Slack 수신·업무 차단 인수는 별도입니다.

자동 연결을 이미 켠 운영 설치의 HTTP/auth 9개 읽기 검사만 수행하려면 `validate_http.py`에 `--read-only-operational`을 명시합니다. 이 옵션은 합성 사건·승인·로그·경보 변경 도구의 guard를 완화하지 않습니다.

## 장애와 알림

로그 수집 Lambda는 300초 제한, 입력 4MiB·10,000개 수용 한도를 사용합니다. 이는 10,000개 전량의 시간·성공 보장이 아닙니다. 리전 간 왕복·throttling·재시도를 고려해 실제 소규모 부하 시험 후 규모를 늘립니다. 사건 생성은 서비스당 시간당 기본 30건이며 고유 관측 건수와 분리합니다.

Lambda 비동기 수집은 최대 두 번 재시도하고 1시간의 이벤트 수명을 적용합니다. 실패는 같은 리전의 전용 private SQS 목적지에 보관합니다. `Errors`, `AsyncEventsDropped`, `DestinationDeliveryFailures`, 큐 depth를 확인합니다. 큰 입력의 실패 기록은 SQS/비동기 메시지 한도로 전달되지 않을 수 있으므로 경보와 원본 로그를 함께 확인합니다.

EventBridge 대상·DLQ는 호환되는 CMK와 정확한 service/key 권한을 사용합니다. 지역 릴레이는 설치의 정확한 네 알람 이름만 중앙으로 보내며, Event bus 대상에는 사용자 지정 RetryPolicy를 넣지 않습니다. 중앙 SNS 게시 내용은 AlarmName/NewStateValue입니다. 알림 비활성 설치에서는 Slack 전달이 이뤄지지 않으므로 회사 운영에서는 실제 수신 가능한 채널을 인수합니다.

DLQ를 장애 함수에 자동 연결해 무조건 재실행하지 않습니다. 원인 해결 후 Lambda requestPayload와 EventBridge 원본을 구분하고 계정·서비스·원본 로그·정책을 확인해 원래 경로로 재전달합니다. claim·발행 revision·영구 영수증을 보존해 중복을 막습니다. 실패 큐 전달 자체가 실패한 경보와 지역 릴레이 장애도 지역 콘솔에서 확인합니다.

## 업데이트·백업·해제

검토한 새 릴리스의 ZIP·manifest·source/lock을 사용하고 같은 설치 ID·외부 설정·S3 state를 유지합니다. Slack·scope·자동 연결·dry run 등 유지할 값을 외부 tfvars에 명시합니다. 새 Terraform plan에서 resource address·현재 물리 ID·alias·IAM·암호화와 변경/삭제/교체를 검토합니다. `prevent_destroy` 같은 수명 정책이 있어도 모든 변경 위험을 대신 검토하지는 않습니다. 회사 계획을 확인한 뒤 저장된 그 plan을 적용합니다.

DynamoDB PITR·삭제 보호, S3 버전·KMS·Retain과 로그 보존을 확인합니다. 세션/리스의 TTL 삭제는 비동기이며 응답·발행 영수증은 TTL로 지우지 않습니다. 오래된 Lambda 버전·아티팩트·Retain 자산의 비용과 정리도 회사가 검토합니다. 복원은 업무 서비스의 현재 WAF 설정·등록 revision·작업 영수증과 대조하고 실제 복구를 연습합니다.

서비스 해제와 플랫폼 제거는 별도 변경 작업입니다. 등록 비활성화·감사 export·해당 namespace 규칙의 검토된 제거·Retain 자산 보존 순서로 수행합니다. 설치 이름 변경·태그 해제·관찰 모드 전환을 삭제 명령으로 사용하지 않습니다.

## 기존 CloudFormation 설치 이관

legacy `install.py`가 관리하는 리소스에 native Terraform을 새 생성으로 적용하지 않습니다. Terraform과 CloudFormation이 같은 리소스를 동시에 갱신하지 않도록 소유권 이관·import를 별도 검토합니다. 현재 물리 이름·ARN·KMS 키·Cognito 사용자/클라이언트·테이블/버킷·함수 alias·큐·이벤트 연결을 보존하며 회사별 physical names와 import 자료는 저장소 밖에 둡니다.

이관 전 state와 감사·사건·등록부·응답 영수증을 백업하고 자동 재조정을 중단할 변경 창을 정합니다. 기존 CFN 리소스의 보존 정책과 분리 절차를 검토한 뒤 정확한 Terraform 주소로 import하고, **예상치 않은 삭제·교체·데이터 초기화가 없는 plan**을 확인합니다. 이관을 위해 Cognito나 DynamoDB·S3·IPSet을 재생성하지 않습니다. 같은 WAF 규칙·주소·ACL 연결·등록부 항목은 계속 런타임 소유이며 Terraform이 전체 목록을 덮어쓰지 않습니다.

CFN 이관 완료와 Terraform apply·런타임 인수는 각각 증거를 남깁니다. legacy 스택의 `Retain`과 Terraform state 백업은 별개이며, 소유권이 정리되기 전 legacy installer를 다시 실행하지 않습니다.

### 1. 회사별 원본과 물리 ID 수집

이관 자료와 작업용 제품 복사본은 모두 공개 checkout 밖의 회사 디렉터리에 둡니다. 기존 설치의 각 스택·리전마다 다음 **세 응답**을 같은 시점의 snapshot으로 수집합니다.

- `DescribeStacks`: 정확한 StackId·이름·안정 상태·태그·현재 Parameters·Outputs.
- `GetTemplate`의 `TemplateStage=Original`: 실제 배포한 원본 `TemplateBody`.
- `ListStackResources`: **모든 페이지**의 `StackResourceSummaries`. CLI 자동 pagination을 사용하거나 끝까지 NextToken을 따라 합치며 첫 페이지·`--max-items`로 잘린 결과를 사용하지 않습니다.

import 도구의 파일명은 `foundation-snapshot.json`, `governance-snapshot.json`, 선택 `ingress-snapshot.json`입니다. 각 파일은 다음 구조로 위 응답을 감쌉니다. 원본 template·응답은 보안 설정과 회사 식별자를 포함할 수 있어 공개 이슈에 첨부하지 않습니다.

```json
{
  "stack": {"Stacks": ["<DESCRIBE_STACKS_OBJECT>"]},
  "template": {"TemplateBody": "<ORIGINAL_TEMPLATE_OBJECT_OR_JSON_STRING>"},
  "resources": {"StackResourceSummaries": ["<ALL_PAGES_RESOURCE_OBJECTS>"]}
}
```

위 문자열은 구조를 설명하는 placeholder이며 실제 배열 항목은 AWS 응답 객체를 그대로 넣습니다. 수집 계정·설치 태그·StackId·region·실제 리소스 수와 페이지 완료를 교차 검증합니다. `DELETE_COMPLETE` 이력과 현재 살아 있는 리소스를 구분합니다. 추가 ingress 리전이 있는 회사는 이 예제의 단일 ingress 파일만으로 전체가 포함됐다고 판단하지 않고 모든 지역의 주소·물리 ID 매핑을 독립 검토합니다.

아래 조회를 각 스택에 반복하고 `$SnapshotName`을 `foundation`, `governance`, `ingress`로 지정합니다. `$SnapshotStack`·`$SnapshotRegion`은 실제 소유 스택에 맞게 정합니다. 리소스 목록 명령에는 pagination을 중단하는 옵션을 넣지 않습니다.

```powershell
$SnapshotDirectory = Join-Path $CompanyDirectory 'migration-snapshots'
New-Item -ItemType Directory -Path $SnapshotDirectory -Force | Out-Null
$SnapshotName = 'foundation'
$SnapshotStack = '<OWNED_STACK_NAME>'
$SnapshotRegion = $ControlRegion
$StackResponse = aws cloudformation describe-stacks --stack-name $SnapshotStack --profile $CompanyProfile --region $SnapshotRegion --output json --no-cli-pager
if ($LASTEXITCODE -ne 0) { throw 'DescribeStacks failed' }
$TemplateResponse = aws cloudformation get-template --stack-name $SnapshotStack --template-stage Original --profile $CompanyProfile --region $SnapshotRegion --output json --no-cli-pager
if ($LASTEXITCODE -ne 0) { throw 'GetTemplate Original failed' }
$ResourceResponse = aws cloudformation list-stack-resources --stack-name $SnapshotStack --profile $CompanyProfile --region $SnapshotRegion --output json --no-cli-pager
if ($LASTEXITCODE -ne 0) { throw 'ListStackResources failed' }
$AllResources = $ResourceResponse | ConvertFrom-Json
if ($AllResources.NextToken) { throw 'Incomplete resource pagination' }
$Snapshot = @{
    stack = ($StackResponse | ConvertFrom-Json)
    template = ($TemplateResponse | ConvertFrom-Json)
    resources = $AllResources
}
$Snapshot | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $SnapshotDirectory "$SnapshotName-snapshot.json") -Encoding utf8
```

```powershell
$SnapshotDirectory = Join-Path $CompanyDirectory 'migration-snapshots'
$ImportSpec = Join-Path $CompanyDirectory 'migration-import-spec.json'
python .\tools\terraform_imports.py --snapshots $SnapshotDirectory --output $ImportSpec --profile $CompanyProfile
```

도구는 mutation 없이 STS와 제한된 API/Cognito 이름·기존 Lambda permission SID를 읽어 `physical_names`, 정확한 native import 주소/ID, 보존할 기존 Lambda version 목록을 준비합니다. 그 JSON은 private이며 `physical_names`는 외부 tfvars로 옮겨 현재 이름을 유지합니다. 한 참조 매핑의 204개 import는 규모 참고값이며 회사별 기대 개수를 고정하지 않습니다. bucket 하나의 정책·versioning·암호화가 여러 Terraform 리소스로 분리될 수 있어 CFN 개수와 같지 않습니다.

AWS provider 6.x의 regional import ID는 `<IMPORT_ID>@<AWS_REGION>`처럼 **명시적인 region suffix**를 사용합니다. 도구가 검토한 regional 유형에만 이를 붙이며 IAM 같은 global 유형에는 붙이지 않습니다. default provider region이 다른 수집 리전의 리소스를 대신하게 두거나 알 수 없는 유형의 ID를 추측하지 않습니다. 기존 Lambda version은 읽기 검토 후 보존하며, 새 생성으로 대체하지 않습니다. 아티팩트 버킷·객체·현재 버전 등 CFN 밖의 자산도 별도 소유권·state 매핑에 포함합니다.

### 2. 임시 private freeze와 import-only 계획

원본 공개 모듈의 hash를 보관하고 **private 작업 복사본에서만** 임시 `lifecycle.ignore_changes=all` freeze를 사용해 기존 resource를 state에 등록할 import 계획을 만듭니다. 이 임시 freeze는 공개 기본 모듈이나 최종 운영 구성에 커밋하지 않습니다. import ID와 대상 주소는 검토한 private spec에서만 가져옵니다.

```powershell
$PrivateTerraformRoot = '<PRIVATE_WORK_COPY_TERRAFORM_DIRECTORY>'
$ImportPlan = Join-Path $CompanyDirectory 'migration-import.tfplan'
$ImportPlanJson = Join-Path $CompanyDirectory 'migration-import-plan.json'
terraform "-chdir=$PrivateTerraformRoot" show -json $ImportPlan | Set-Content -LiteralPath $ImportPlanJson -Encoding utf8
python .\tools\terraform_migration_guard.py --plan-json $ImportPlanJson --phase import
if ($LASTEXITCODE -ne 0) { throw 'Import plan failed the migration guard' }
terraform "-chdir=$PrivateTerraformRoot" apply -input=false $ImportPlan
```

이 명령 전의 plan 생성에는 회사의 외부 backend·tfvars와 정확한 import 정의를 사용합니다. guard는 완전하고 오류 없는 계획의 `no-op`·`read`만 허용합니다. import는 알려진 `importing.id`와 `no-op`이어야 하며 create/update/delete/replace/forget, 알 수 없는 동작, 실패·error·unknown check는 거절합니다. 이 apply 단계는 state 등록만 해야 하며 실행 코드·환경·WAF·업무 데이터 변경을 섞지 않습니다.

### 3. freeze 해제와 native 인수 계획

임시 all-fields freeze를 제거하고 검토된 공개 기본 구성으로 native 계획을 다시 만듭니다. 기존 물리 이름·키·Cognito client·테이블·로그·큐·함수 alias·runtime hash와 import 대상이 맞는지 확인합니다. 기존 browser client에 ClientSecret이 없음을 확인하고 `generate_secret`의 제한된 import 차이만 유지합니다.

```powershell
$AdoptionPlan = Join-Path $CompanyDirectory 'migration-adoption.tfplan'
$AdoptionPlanJson = Join-Path $CompanyDirectory 'migration-adoption-plan.json'
terraform "-chdir=$PrivateTerraformRoot" show -json $AdoptionPlan | Set-Content -LiteralPath $AdoptionPlanJson -Encoding utf8
python .\tools\terraform_migration_guard.py --plan-json $AdoptionPlanJson --phase adoption
if ($LASTEXITCODE -ne 0) { throw 'Native adoption plan failed the migration guard' }
```

여기서는 `--allow-create-address`를 전달하지 않아 **create 0**, 삭제·교체·forget 0을 요구합니다. 허용되는 in-place update도 IAM·Cognito·함수 환경·코드·암호화 의미를 개별 검토하며 guard 통과를 무변경 증거로 해석하지 않습니다. 별도 신규 리소스가 필요하다면 원래 이관에 섞지 않고 회사 변경으로 검토합니다. 도구는 `--allow-create-address`를 정확한 주소로 반복 지정할 수 있지만 wildcard를 허용하지 않습니다.

### 4. CFN 보존 확인과 소유권 해제

native apply 전, CFN이 같은 리소스를 계속 관리하지 않도록 순서를 정합니다. CFN의 **모든 live resource**에 `DeletionPolicy=Retain`과 `UpdateReplacePolicy=Retain`을 적용할 보존 전용 변경 집합을 만듭니다. 원본 Properties·Parameters·Outputs·물리 ID를 바꾸지 않는 metadata/보존 정책 변경인지 실제 change set을 확인하고, Add/Remove·replacement·예상 밖 property 수정은 중단합니다. StackPolicy로 `Update:Replace`와 `Update:Delete`도 차단하고 현재 물리 ID를 다시 대조합니다.

적용 후 새 Original template와 모든 페이지의 live LogicalResourceId 목록을 다시 수집합니다. 다음 guard의 입력은 두 Retain이 실제로 적용된 그 snapshot입니다.

```powershell
$RetainedTemplate = Join-Path $CompanyDirectory 'migration-retained-template.json'
$LiveLogicalIds = Join-Path $CompanyDirectory 'migration-live-logical-ids.json'
$ResolvedConditions = Join-Path $CompanyDirectory 'migration-condition-values.json'
python .\tools\terraform_migration_guard.py --template-json $RetainedTemplate --actual-resource-ids-json $LiveLogicalIds --conditions-json $ResolvedConditions
if ($LASTEXITCODE -ne 0) { throw 'CFN retention or resource coverage check failed' }
```

`$RetainedTemplate`은 TemplateBody 객체, `$LiveLogicalIds`는 현재 모든 live LogicalResourceId의 JSON 배열입니다. 두 집합이 일치해야 하며, template에 선언된 Condition을 현재 Parameters로 별도 평가해 **정확히 false**로 확인한 부재 리소스만 예외입니다. 단순히 목록에 없다는 이유로 false를 추정하지 않습니다. 실제 존재하는 리소스는 조건값과 무관하게 두 Retain이 필요합니다.

state import 범위·리소스별 Retain·변경 집합·StackPolicy·물리 ID 재검증을 마친 뒤 회사의 검토된 절차로 CFN **stack container만 release**하고 기존 리소스가 보존됐는지 다시 조회합니다. StackPolicy는 stack 삭제 자체의 보호 장치가 아니므로 이것만 믿고 container를 해제하지 않습니다. 각 단계 실패 시 후속 native 변경을 진행하지 않고 보존된 자원·state·감사 기록을 확인합니다.

### 5. native apply와 실제 인수

CFN 소유권이 해제되고 실제 ID가 유지됐음을 확인한 뒤, freeze 없는 native 구성을 새로 계획·guard하고 그 저장 계획을 apply합니다. 이어 다시 plan하여 **No changes**인지 확인합니다. 예전 저장 계획을 상태 변경 이후 재사용하지 않습니다.

배포 출력·함수 코드 hash/alias·IAM·Cognito MFA/PKCE·HTTPS·자동 연결 상태·수집/사건/게시·전달을 실제 AWS 메타데이터로 인수합니다. 기존 live 사건·등록부 revision·응답 tombstone·감사 데이터·정확한 WAF 주소를 보존하며 임의 테스트 차단을 실행하지 않습니다. 이관 계획 통과, state 등록, CFN 해제, native apply, no-changes plan, 실제 서비스 보호 인수는 각각 별도의 결과로 기록합니다. 이 절차는 회사마다 독립 검토하며 참조 환경의 개수나 성공 기록을 회사의 성공으로 대체하지 않습니다.
