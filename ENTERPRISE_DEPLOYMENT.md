# 기업 AWS 보안 설치 안내

이 공개 저장소는 기업의 AWS 계정에 **Terraform을 기본 경로**로 설치하는 제품 코드와 문서입니다. 사전 빌드 ZIP의 정적 Terraform 모듈과 런타임·대시보드 아티팩트를 사용하면 설치에 Python·Node/npm이 필요하지 않습니다. 회사 tfvars·backend·AWS 자격증명·관리자 이메일·Slack 식별자·계획·배포 출력은 저장소 밖에 두고 state는 회사 private S3 backend에 보관합니다.

| 문서 | 내용 |
|---|---|
| [빠른 설치](docs/quickstart.md) | 도구 준비, 외부 회사 설정, 빌드·로컬 계획, 검증 설치, 운영 전환, 최초 관리자 |
| [구성](docs/configuration.md) | 설치 schema·태그·Slack App과 Secret·선택 모델·서비스 정책 |
| [구조](docs/architecture.md) | 발견·WAF·HOTL/HITL·게시·Slack·대시보드·지역 경보 흐름 |
| [운영](docs/operations.md) | 실제 인수, 차단 롤백, 실패 큐, 검증 도구, 업데이트·백업·해제 |
| [보안 경계](docs/security-boundaries.md) | 지원 대상·원본 로그·trusted writer IAM·인증·데이터 경계 |
| [서비스 정책](SERVICE_POLICY.md) | 등록된 서비스의 observe/enforce·HITL·자동 차단·보호 CIDR |
| [참고 프로젝트](docs/upstream-references.md) | AWS WAF 자동화, Cloud Custodian, Prowler의 참고 패턴과 설계 차이 |

기본은 공개 ALB·활성 CloudFront의 태그 선택과 observe/dry run입니다. 업무 애플리케이션이나 취약 실습 웹사이트를 만들지 않습니다. 전체 AWS 서비스 보호·회사 IAM 자동 교정·CloudTrail/GuardDuty 자동 분석·일반 포렌식 생성을 완료했다고 표현하지 않습니다.

먼저 `automatic_onboarding_enabled=false`·observe·`default_dry_run=true`로 플랫폼을 배포하고 실제 함수·인증·후보·충돌을 확인합니다. 자동 연결을 명시적으로 활성화한 뒤에는 observe에서도 실제 WAF 연결·규칙·로그 설정이 바뀔 수 있습니다. enforce 전 회사 IAM writer 경계·오리진·오탐·부하·관리자 로그인·Slack 수신·실제 차단과 롤백을 인수합니다. 기존 Python/CloudFormation 설치는 legacy이며 [소유권 이관](docs/operations.md#기존-cloudformation-설치-이관) 전 native Terraform과 중복 관리하지 않습니다.
