# Terraform으로 설치

기본 설치는 `terraform/`의 native AWS provider 리소스를 사용합니다. 회사 AWS 계정마다 설치하며 다른 회사의 설정·state·ARN을 재사용하지 않습니다. 기존 `install.py`와 CloudFormation 템플릿은 legacy 호환 경로로 남아 있습니다. 기존 설치는 먼저 [이관 경계](operations.md#기존-cloudformation-설치-이관)를 확인합니다.

## 사전 빌드 패키지로 설치

Terraform 1.12 이상 2 미만을 준비합니다. 검증 버전은 1.16.3이며 provider는 커밋된 `.terraform.lock.hcl`로 고정합니다. 사전 빌드 설치에는 Python·Node/npm이 필요하지 않습니다. 회사 AWS 자격증명을 준비하고 프로필·SSO 및 운영 CLI를 사용한다면 AWS CLI v2도 설치합니다.

[v0.2.0 GitHub Release](https://github.com/typemnm/enterprise-security-platform/releases/tag/v0.2.0)의 Terraform 배포 ZIP과 SHA-256 파일을 함께 사용합니다. v0.1.0 ZIP은 이전 Python/CloudFormation 패키지입니다.

```powershell
$ReleaseTag = 'v0.2.0'
$ReleaseBase = "https://github.com/typemnm/enterprise-security-platform/releases/download/$ReleaseTag"
$PackageDirectory = Join-Path $env:TEMP "enterprise-security-platform-$ReleaseTag"
New-Item -ItemType Directory -Path $PackageDirectory -Force | Out-Null
$DeployZip = Join-Path $PackageDirectory 'enterprise-security-platform-deploy.zip'
$ChecksumFile = "$DeployZip.sha256"
Invoke-WebRequest -Uri "$ReleaseBase/enterprise-security-platform-deploy.zip" -OutFile $DeployZip
Invoke-WebRequest -Uri "$ReleaseBase/enterprise-security-platform-deploy.zip.sha256" -OutFile $ChecksumFile
$ExpectedSha256 = ((Get-Content -LiteralPath $ChecksumFile -Raw).Trim() -split '\s+')[0]
if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid SHA-256 file' }
if ((Get-FileHash -LiteralPath $DeployZip -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Deployment ZIP checksum mismatch' }
Expand-Archive -LiteralPath $DeployZip -DestinationPath $PackageDirectory
Set-Location (Join-Path $PackageDirectory 'enterprise-security-platform')
```

패키지에는 `terraform/`과 잠금 파일, `build/release/runtime.zip`, `dashboard.zip`, `manifest.json`, 같은 release ID의 테스트 결과가 들어 있습니다. 회사 파일은 추출 디렉터리 밖에 둡니다.

## 회사 설정과 state 준비

AWS 프로필·자격증명은 회사의 기존 AWS credential chain을 사용합니다. Access key를 provider, tfvars, backend 파일에 적지 않습니다. 설치 역할은 계획에 나오는 IAM/PassRole·Lambda·DynamoDB·KMS·S3·로그·EventBridge·SNS/SQS·Cognito·HTTP API·SFN 구성 권한과 state backend 권한을 가져야 합니다.

```powershell
$CompanyDirectory = Join-Path $env:USERPROFILE 'company-security'
New-Item -ItemType Directory -Path $CompanyDirectory -Force | Out-Null
$CompanyVars = Join-Path $CompanyDirectory 'production.tfvars'
$BackendConfig = Join-Path $CompanyDirectory 'backend.hcl'
$PlanFile = Join-Path $CompanyDirectory 'production.tfplan'
$DeploymentOutputs = Join-Path $CompanyDirectory 'deployment-outputs.json'
$ControlRegion = 'ap-northeast-2'
$env:AWS_PROFILE = 'company'
$env:TF_DATA_DIR = Join-Path $CompanyDirectory 'terraform-data'
```

`$CompanyVars`에 아래 값을 회사 환경에 맞게 저장합니다. `account_id`를 실제 회사 계정으로 바꾸고 `release_id`에는 선택 릴리스의 `build/release/manifest.json` 값을 넣습니다. 공개 ALB·CloudFront의 실제 ARN이나 고객 도메인은 필수 입력이 아닙니다.

```hcl
installation_id              = "company-security-prod"
environment                  = "prod"
account_id                   = "<COMPANY_ACCOUNT_ID>"
control_region               = "ap-northeast-2"
discovery_regions            = ["ap-northeast-2", "us-east-1"]
installation_scope           = "tagged"
response_mode                = "observe"
allowed_actions              = ["monitor", "block_ip"]
principal_scopes             = []
exclude_tags                 = { "security:exclude" = "true" }
automatic_onboarding_enabled = false
default_dry_run              = true
release_id                   = "<MANIFEST_RELEASE_ID>"
```

state용 private S3 버킷과 KMS 키를 회사가 준비합니다. 버전 관리·public access block·TLS·접근 제한을 적용하고 state lock 파일 사용 권한도 허용합니다. `terraform/bootstrap-state/`는 새 backend를 만드는 선택 경로입니다. bootstrap 자체 state는 회사 외부 경로에 보관하며 기존 보안 backend가 있다면 재사용합니다.

새 backend가 필요할 때만 외부 `state-bootstrap.tfvars`에 `region`, `account_id`, 전역에서 고유한 `state_bucket_name`, `installation_id`를 지정하고 다음을 실행합니다. bootstrap과 본 설치는 다른 데이터 디렉터리·state를 사용합니다.

```powershell
$BootstrapVars = Join-Path $CompanyDirectory 'state-bootstrap.tfvars'
$BootstrapState = Join-Path $CompanyDirectory 'state-bootstrap.tfstate'
$BootstrapPlan = Join-Path $CompanyDirectory 'state-bootstrap.tfplan'
$env:TF_DATA_DIR = Join-Path $CompanyDirectory 'bootstrap-terraform-data'
terraform -chdir=terraform/bootstrap-state init -input=false -lockfile=readonly "-backend-config=path=$BootstrapState"
terraform -chdir=terraform/bootstrap-state plan -input=false "-var-file=$BootstrapVars" "-out=$BootstrapPlan"
terraform -chdir=terraform/bootstrap-state show -no-color $BootstrapPlan
terraform -chdir=terraform/bootstrap-state apply -input=false $BootstrapPlan
terraform -chdir=terraform/bootstrap-state output -json backend
$env:TF_DATA_DIR = Join-Path $CompanyDirectory 'terraform-data'
```

마지막 backend 출력은 회사 자료입니다. 다음 파일에 필요한 값을 옮기고 bootstrap state를 별도 백업합니다. state 버킷·키의 제거는 일반 플랫폼 삭제와 분리합니다.

`$BackendConfig`에는 다음 회사 backend 값만 넣습니다. 자격증명은 넣지 않습니다.

```hcl
bucket       = "<COMPANY_STATE_BUCKET>"
key          = "security-platform/prod/terraform.tfstate"
region       = "<STATE_BUCKET_REGION>"
encrypt      = true
use_lockfile = true
kms_key_id   = "<COMPANY_STATE_KMS_KEY_ARN>"
```

회사 tfvars·backend·state·plan·출력은 비공개 자료입니다. Terraform의 `sensitive` 표시는 state 값을 암호화하거나 제거하지 않습니다. Slack token·비밀번호·승인 token을 Terraform에 입력하거나 Secret 값 조회 data source로 읽지 않습니다. 자세한 설정은 [구성](configuration.md)을 따릅니다.

## 계획과 검증 배포

```powershell
terraform -chdir=terraform init -input=false -lockfile=readonly "-backend-config=$BackendConfig"
terraform -chdir=terraform validate
terraform -chdir=terraform plan -input=false "-var-file=$CompanyVars" "-out=$PlanFile"
terraform -chdir=terraform show -no-color $PlanFile
terraform -chdir=terraform apply -input=false $PlanFile
terraform -chdir=terraform output -json deployment | Set-Content -LiteralPath $DeploymentOutputs -Encoding utf8
```

Terraform plan은 backend와 AWS 조회·refresh를 수행할 수 있습니다. 기존 Python 설치기의 AWS 0호출 `--plan`과 의미가 다릅니다. 계획에서 계정·리전·설치 이름·IAM·암호화·백업·변경 및 삭제/교체를 검토합니다. state·저장 계획·`terraform show -json` 결과를 공개 CI나 이슈에 올리지 않습니다.

첫 배포는 `automatic_onboarding_enabled=false`, `observe`, `default_dry_run=true`, Slack·모델 미설정을 유지합니다. 인프라 배포 완료와 실제 함수 코드·Cognito·HTTP·사건 흐름 인수 성공은 별도로 검증합니다. [운영 검증](operations.md)을 수행하고 회사 증거는 외부에 보관합니다.

## 후보 검토와 운영 전환

업무 서비스의 후보·공유 ACL·기존 규칙과 로그 충돌을 조회합니다. Python은 선택 운영 CLI에만 필요하며 기본 Terraform 배포에는 필요하지 않습니다. 배포 출력 기반 CLI 명령은 [운영](operations.md)에 있습니다.

후보와 회사 IAM writer 경계를 검토한 뒤 외부 tfvars의 `automatic_onboarding_enabled=true`를 새 plan/apply로 반영합니다. 자동 발견이 켜지면 주기·생성/태그 이벤트로 실제 WAF 연결·규칙·로그 수집 조정이 실행될 수 있습니다. Terraform apply 자체가 업무 reconcile CLI를 실행하지는 않습니다. 즉시 조정은 운영자가 명시적으로 reconcile을 요청합니다.

`observe`·dry run은 대응 IP 차단을 제한하며 최초 WAF 연결은 막지 않습니다. `all-supported`를 선택하면 `acknowledge_all_supported=true`도 필요합니다. 실제 차단은 설치의 `default_dry_run=false`, `acknowledge_enforcement=true`와 [등록된 서비스 정책](../SERVICE_POLICY.md), 현재 사건·증거·승인 검증을 모두 충족한 뒤에만 허용합니다. 기존 등록 서비스의 정책은 설치 변수 변경만으로 덮어쓰지 않습니다.

관리자 초대와 Slack 연결은 [구성](configuration.md)을 따릅니다. 기본 관리자 이메일·비밀번호·Slack 계정은 없습니다.

## 소스에서 빌드하는 경우

Python 3.10 이상, Node.js 24.x(24.11 이상)·npm과 Terraform을 준비합니다.

```powershell
python -m pip install -r .\tests\requirements.txt
python .\build_release.py --build
python .\tools\pack_release.py
```

빌드는 잠긴 Python SDK와 Node 의존성, 런타임·대시보드 시험, legacy CFN 템플릿과 Terraform 소스·잠금 파일을 검증·해시화합니다. 생성기 Python은 개발 도구이며 Terraform 모듈은 생성된 AWS provider 리소스를 직접 배포합니다.
