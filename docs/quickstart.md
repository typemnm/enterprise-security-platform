# 빠른 설치

이 문서의 작업 디렉터리는 제품 루트입니다. 예시 프로필 `company`와 설정 값을 회사 환경에 맞게 바꿉니다. 설치는 회사 AWS 계정마다 수행하며 다른 회사의 ARN·설정·인수 기록을 재사용하지 않습니다.

## 사전 빌드 패키지로 설치

Python 3.10 이상과 AWS CLI v2를 준비합니다. 이 경로는 Node/npm 빌드를 실행하지 않습니다. [v0.1.0 GitHub Release](https://github.com/typemnm/enterprise-security-platform/releases/tag/v0.1.0)의 배포 ZIP과 SHA-256 파일을 함께 받고 체크섬을 검증합니다.

```powershell
$ReleaseBase = 'https://github.com/typemnm/enterprise-security-platform/releases/download/v0.1.0'
$PackageDirectory = Join-Path $env:TEMP 'enterprise-security-platform-v0.1.0'
New-Item -ItemType Directory -Path $PackageDirectory -Force | Out-Null
$DeployZip = Join-Path $PackageDirectory 'enterprise-security-platform-deploy.zip'
$ChecksumFile = "$DeployZip.sha256"
Invoke-WebRequest -Uri "$ReleaseBase/enterprise-security-platform-deploy.zip" -OutFile $DeployZip
Invoke-WebRequest -Uri "$ReleaseBase/enterprise-security-platform-deploy.zip.sha256" -OutFile $ChecksumFile
$ExpectedSha256 = ((Get-Content -LiteralPath $ChecksumFile -Raw).Trim() -split '\s+')[0]
if ($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid SHA-256 file' }
$ActualSha256 = (Get-FileHash -LiteralPath $DeployZip -Algorithm SHA256).Hash
if ($ActualSha256 -ne $ExpectedSha256) { throw 'Deployment ZIP checksum mismatch' }
Expand-Archive -LiteralPath $DeployZip -DestinationPath $PackageDirectory
Set-Location (Join-Path $PackageDirectory 'enterprise-security-platform')
```

패키지는 `enterprise-security-platform/` 아래에 코드·문서, `build/release/runtime.zip`, `dashboard.zip`, `manifest.json`과 릴리스에 대응하는 `build/test-validation-result.json`을 포함합니다. `install.py`가 manifest와 소스·템플릿·배포 아티팩트 해시를 검사합니다. 이 경로에서는 아래의 소스 빌드 절을 건너뛰고 외부 설정과 로컬 계획부터 진행합니다. 회사 설정은 추출 디렉터리 밖에 보관합니다.

## 소스에서 빌드하는 경우

Python 3.10 이상, AWS CLI v2에 더해 Node.js 24.x(24.11 이상)와 npm을 준비합니다.

```powershell
git clone https://github.com/typemnm/enterprise-security-platform.git
Set-Location enterprise-security-platform
```

## 준비와 외부 설정

두 설치 경로 모두 회사의 설치 프로필은 CloudFormation·아티팩트 S3·IAM/PassRole·Lambda·DynamoDB·KMS·로그·EventBridge·SNS/SQS·Cognito·HTTP API 구성에 필요한 권한을 가져야 합니다. 실제 범위는 생성 템플릿과 회사 권한 경계를 검토해 정하며, 저장소는 AWS 자격증명을 제공하지 않습니다.

PowerShell에서는 아래처럼 고객 설정을 저장소 밖에 둡니다. macOS/Linux에서도 저장소 밖 경로를 `--config`에 전달하는 원칙은 같습니다.

```powershell
$CompanyConfigDirectory = Join-Path $env:USERPROFILE 'company-security'
New-Item -ItemType Directory -Path $CompanyConfigDirectory -Force | Out-Null
$CompanyConfig = Join-Path $CompanyConfigDirectory 'installation.json'
$CompanyProfile = 'company'
$ControlRegion = 'ap-northeast-2'
Copy-Item -LiteralPath .\service-onboarding\installation.example.json -Destination $CompanyConfig
python -m pip install -r .\service-onboarding\requirements.txt
python .\service-onboarding\onboard.py --config $CompanyConfig --validate
```

예제 파일의 `installation_id`, `environment`, 발견 리전·범위와 제외 태그를 검토합니다. 회사 계정을 고정하려면 외부 파일에 선택 `account_id`를 넣습니다. 생략하면 설치 프로필의 STS 계정을 확인합니다. 업무 서비스 ARN이나 고객 도메인은 필수 입력이 아닙니다. 자세한 필드는 [구성](configuration.md)을 따릅니다.

## 소스 빌드와 로컬 계획

소스 빌드 경로에서만 다음을 실행합니다. 사전 빌드 패키지는 이 단계를 생략합니다.

```powershell
python -m pip install -r .\tests\requirements.txt
python .\build_release.py --check
python .\build_release.py --build
```

빌드는 Python SDK·전체 의존성 wheel의 버전과 해시를 확인하고, Node 의존성을 잠긴 파일에서 설치하며, 테스트·템플릿·릴리스 해시를 검사합니다. Node 배포 파일은 깨끗한 설치 직후의 파일별 해시와 시험 후·ZIP·설치 시점을 대조합니다. 공개 패키지 저장소 또는 검증한 pip 캐시 접근이 필요합니다.

두 경로 모두 준비된 릴리스로 로컬 계획을 확인합니다.

```powershell
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --plan
```

`--plan`은 AWS에 연결하지 않는 설정 계획입니다. 실제 리소스 후보·권한·기존 WAF 충돌·비용까지 검증하는 명령은 아닙니다. 릴리스 시험과 회사별 운영 인수의 차이는 [검증 상태](verification.md)를 참고합니다.

## 업무 변경 없는 플랫폼 검증 설치

외부 설정의 기본 `observe`·`tagged`를 유지합니다.

```powershell
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --plan --validation-only
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --apply --validation-only
```

이 명령은 회사 계정에 실제 제어 영역·지역 수집 함수·governance·HTTPS 대시보드를 배포합니다. 자동 연결 이벤트는 계속 꺼 두고 조회용 discovery만 수행합니다. WAF 재조정·실제 IP 차단·Slack 활성화·관리자 초대는 하지 않습니다. CloudFront 수집을 위해 `us-east-1` 영역도 포함합니다.

`build/install-result.json`의 `VALIDATED_AUTOMATIC_ONBOARDING_DISABLED`는 플랫폼 검증 결과이며 업무 서비스 보호 완료가 아닙니다. 생성 결과는 회사 내부 증거로 보관하고 공개 Git에 커밋하지 않습니다. [운영 검증 도구](operations.md)의 합성 시험을 추가 실행할 수 있습니다.

## 후보 조회와 운영 전환

```powershell
python .\service-onboarding\onboard.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --discover
```

후보의 계정·리전·기존 ACL·규칙·로깅·공유 여부·검토 사유를 확인합니다. `REVIEW_REQUIRED`를 성공으로 취급하지 않습니다. 생성 API 이벤트를 통한 즉시 발견은 활성 CloudTrail trail의 해당 management 이벤트 전달이 필요합니다. 미설정 또는 이벤트 누락은 5분 주기 발견으로 보완하며, 설치 도구가 회사 CloudTrail을 임의로 만들거나 바꾸지는 않습니다.

회사 변경 절차를 거친 뒤 같은 설치 ID로 `--validation-only`를 빼고 적용합니다.

```powershell
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --plan
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --apply
```

**운영 적용은 즉시 자동 발견과 WAF 연결·규칙·로그 수집 조정을 실행할 수 있습니다.** observe/dry run은 대응 IP 차단을 제한하지만 최초 WAF 연결을 막지는 않습니다. `all-supported` 설치는 조회·계획·적용 명령에 `--allow-all-supported`도 전달합니다. 실제 대응은 [회사 IAM 인수](security-boundaries.md)와 [서비스 정책](../SERVICE_POLICY.md)을 완료한 뒤 활성화합니다.

## 최초 관리자와 Slack

회사 담당자가 실제 수신할 이메일을 CLI 인자로 명시할 때만 Cognito 초대를 요청합니다.

```powershell
$AdminEmail = '<ADMIN_EMAIL>'
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --plan --admin-email $AdminEmail
python .\install.py --config $CompanyConfig --profile $CompanyProfile --region $ControlRegion --apply --admin-email $AdminEmail
```

설치 결과의 `dashboard_url`을 열고 초대된 계정의 최초 비밀번호 변경·인증 앱 MFA 등록을 완료합니다. `--validation-only`에서는 관리자 초대를 요청할 수 없습니다. 이 명령도 운영 적용이므로 대상 서비스 조정이 실행됩니다.

Slack 연결은 [구성의 Slack 절차](configuration.md#slack-연결)를 따릅니다. 갱신 시 기존 Slack 인자, `--allow-all-supported`, 검토한 `--enable-enforcement` 등 유지할 실행 설정을 함께 전달합니다. 인자를 생략하면 알림 비활성 또는 기본 dry run을 선언합니다.
