# Enterprise Security Platform

기업의 AWS 계정에 직접 설치하는 HTTP 서비스 보안 플랫폼입니다. 보호할 서비스 ARN을 미리 입력하지 않고, 설정한 리전의 **공개 ALB와 활성 CloudFront**를 발견해 WAF·보안 로그·HOTL/HITL·관리자 대시보드·Slack 알림을 연결합니다. 업무 애플리케이션이나 취약 실습 웹사이트는 배포하지 않습니다.

기본은 태그를 통한 선택, `observe`, `dry_run=true`입니다. 운영자가 범위와 정책을 검토한 뒤 실제 대응을 활성화합니다. 관찰 모드에서도 최초 WAF 연결·규칙·로그 설정은 변경될 수 있으므로, 먼저 검증 설치와 실제 후보 조회를 수행합니다.

## 제공하는 기능

- 서비스 생성·태그 변경 이벤트와 주기적 발견에 따른 지원 리소스 연결. 기존 규칙·로깅을 보존하고 공유 ACL 등의 충돌은 `REVIEW_REQUIRED`로 중단합니다.
- AWS Step Functions의 HOTL 자동 대응과 HITL 승인·반려 흐름. 보고서 요약, 추천 행동, **결정된 행동과 실제 성공·실패·모의 실행 결과**를 Slack에 전달합니다.
- Cognito MFA·Authorization Code + PKCE 로그인, 서비스별 관리자 권한, 비공개 사건·감사 기록.
- HOTL 대시보드의 차단 롤백. 사건에 연결된 영구 WAF IPSet에서 해당 IP의 정확한 `/32` 또는 `/128`만 제거합니다.
- 고정한 의존성, 해시를 확인하는 설치, 백업·보존·실패 큐·운영 경보.

직접 WAF 연결의 지원 범위는 공개 ALB와 CloudFront입니다. NLB/TCP·RDS·직접 노출 EC2·API Gateway 직접 연결, CloudTrail/GuardDuty 자동 분석, 일반 포렌식 생성, AWS Organizations 전체 계정 일괄 설치는 포함하지 않습니다. ALB 뒤의 EC2·ECS·컨테이너 HTTP 서비스는 해당 ALB의 보호 범위에 들어갑니다.

## 시작하기

사전 빌드 패키지는 [v0.1.0 GitHub Release](https://github.com/typemnm/enterprise-security-platform/releases/tag/v0.1.0)의 `enterprise-security-platform-deploy.zip`과 `enterprise-security-platform-deploy.zip.sha256`을 받습니다. [빠른 설치의 체크섬 검증](docs/quickstart.md#사전-빌드-패키지로-설치)을 거친 뒤 ZIP 안의 `enterprise-security-platform/`을 작업 디렉터리로 사용합니다.

사전 빌드 설치에는 Python 3.10 이상, AWS CLI v2, `service-onboarding/requirements.txt`의 jsonschema와 회사 AWS 설치 프로필이 필요합니다. Node/npm 빌드는 필요하지 않습니다. ZIP에는 코드·문서, `build/release/`의 런타임·대시보드 ZIP과 manifest, 해당 릴리스의 테스트 결과가 포함됩니다.

소스를 직접 빌드하려면 Node.js 24.x(24.11 이상)와 npm도 준비하고 저장소를 복제합니다. 모든 명령은 제품 루트에서 실행합니다.

```powershell
git clone https://github.com/typemnm/enterprise-security-platform.git
Set-Location enterprise-security-platform
```

[빠른 설치](docs/quickstart.md)에서 회사 설정을 **저장소 밖**에 만들고, 로컬 계획 → 검증 설치 → 운영 전환 순서로 진행합니다. 회사 계정·관리자 이메일·Slack 채널·Secret ARN·생성된 배포 결과를 공개 저장소에 넣지 않습니다. Token과 비밀번호는 설정 파일이나 소스에 저장하지 않습니다.

| 문서 | 내용 |
|---|---|
| [빠른 설치](docs/quickstart.md) | 준비·빌드·검증 설치·운영 전환·최초 관리자 |
| [구성](docs/configuration.md) | 외부 설치 파일, 발견 태그, Slack 연결, 서비스 정책 |
| [구조](docs/architecture.md) | AWS 데이터 흐름과 배포 모듈 |
| [운영](docs/operations.md) | 인수 검증, 대응·롤백, 실패 복구·업데이트 |
| [보안 경계](docs/security-boundaries.md) | 실제 지원 범위와 enforce 전 IAM 인수 |
| [검증 상태](docs/verification.md) | 소스 시험·릴리스 증거와 실제 운영 인수의 구분 |
| [참고 프로젝트](docs/upstream-references.md) | AWS WAF 자동화·Cloud Custodian·Prowler의 참고 패턴과 차이 |
| [상세 설치 안내](ENTERPRISE_DEPLOYMENT.md) | 설치 문서 진입점 |
| [서비스 정책](SERVICE_POLICY.md) | 서비스별 관찰·자동 차단·HITL 정책 CLI |

저장소의 코드·로컬 테스트 통과와 특정 회사의 운영 인수는 구분합니다. 회사는 실제 서비스의 오탐·오리진 우회·권한·비용, 관리자 로그인, Slack 수신, 실제 차단과 롤백을 자신의 환경에서 확인해야 합니다.

제품 라이선스는 [Apache-2.0](LICENSE)입니다. 포함하는 외부 의존성의 라이선스·NOTICE도 보존하며, 참고 프로젝트와 실제 재사용의 구분은 [참고 프로젝트](docs/upstream-references.md)에 기록합니다.
