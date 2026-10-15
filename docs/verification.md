# 검증 상태

공개 제품의 소스 시험, 배포 패키지의 무결성, 특정 회사 계정의 실제 운영 인수는 별도로 확인합니다. 이 문서에는 개인 계정·배포 URL·Slack 식별자를 포함하지 않습니다.

## Terraform 기본 경로의 검증 계약

새 기본 배포 소스는 `terraform/`이며 v0.1.0의 Python/CloudFormation 설치 증거와 구분합니다. CI는 AWS 자격증명 없이 고정한 Terraform 바이너리 checksum, 커밋된 provider lock, `fmt -check`, `init -backend=false -lockfile=readonly`, `validate`를 확인합니다. `init`은 provider 다운로드를 위해 네트워크를 사용할 수 있으며 회사 backend·계정 apply는 수행하지 않습니다.

빌드는 정적 Terraform 모듈·provider 잠금 파일·생성기까지 source hash와 release ID에 포함합니다. 배포 ZIP은 같은 manifest의 런타임·대시보드와 시험 결과를 담습니다. 모듈·lock의 추가·삭제·변조는 새 manifest 없이 패키징할 수 없으며, 회사 tfvars·state/backup·backend·계획·출력·provider cache는 공개 ZIP에서 제외합니다. 기존 SDK·Node 의존성 파일별 hash와 Lambda 아티팩트 검증도 유지합니다.

Terraform validate·plan·apply 성공, 기존 CFN에서의 소유권 이관 성공, 실제 AWS 런타임·HTTP·HOTL/HITL·전달·회사 서비스 인수는 각각 확인합니다. plan은 AWS 조회를 할 수 있고 apply만으로 실제 Slack·WAF 차단이나 사람의 MFA 로그인이 검증되지는 않습니다. 아래 v0.1.0 이력은 Terraform 배포 성공으로 재사용하지 않습니다.

## v0.2.0 Terraform 참조 이관 확인 상태

기존 참조 설치를 native Terraform으로 이관해 apply가 **추가 0·in-place 갱신 29·삭제 0**으로 완료됐습니다. 기존 CFN 스택 3개의 live 리소스 185개를 Retain으로 보존한 뒤 stack container를 해제했고, 기존 리소스가 유지됐음을 확인했습니다. 이 수치는 이 참조 환경의 결과이며 회사별 import·리소스 개수를 뜻하지 않습니다. 런타임 기능을 교체하는 이관은 수행하지 않았습니다.

최종 릴리스 재빌드와 대응 metadata 재적용, 이후 no-changes plan·HTTPS 재검증은 별도 마감 항목입니다. 위 native apply 성공만으로 이 최종 검사나 실제 회사 Slack·업무 차단·사람의 MFA 로그인까지 완료됐다고 판단하지 않습니다.

## v0.1.0 소스 검증

제품 소스 테스트 301개와 추가 공개·의존성 패키징 테스트 18개가 통과했습니다. Node 의존성은 깨끗한 npm 설치 직후 123개 패키지·6,250개 배포 파일의 해시를 기록하고, 시험 후·ZIP 생성·설치 시 추가·삭제·변조를 거절합니다. 이 결과는 로컬 시험이며 실제 기업 서비스의 공격 차단, Slack 수신, Cognito 로그인, 부하 처리 성공을 대신하지 않습니다.

사전 빌드 [v0.1.0 배포 패키지](https://github.com/typemnm/enterprise-security-platform/releases/tag/v0.1.0)는 SHA-256 파일로 외부 ZIP을 검증합니다. 패키지의 `build/release/manifest.json`에는 소스·템플릿·런타임·대시보드 해시와 `release_id`가 들어가며, `build/test-validation-result.json`의 `release_id`가 같은 릴리스인지 확인합니다. 설치 도구도 manifest에 기록된 파일 해시를 검사합니다.

## v0.1.0 CloudFormation 배포 이력

2026-10-15에 공개 제품 릴리스 `a7ab77f2a0f023bb886d918eb0bc359314387cb2a43a6f0afc01338415109aec`를 외부 계정 설정으로 실제 참조 환경에 적용했습니다. 서울 제어 영역·governance와 `us-east-1` 수집 영역의 CloudFormation 스택 3개가 완료됐고, 설치 도구가 배포 함수 코드 해시·Cognito MFA/관리자 전용 설정·HTTPS health를 확인했습니다.

일반 `--apply`로 자동 발견을 활성화했으며, `tagged`·`observe`·`dry_run=true`를 확인했습니다. 선택 태그가 붙은 지원 서비스는 0개여서 결과는 `DEPLOYED_NO_ELIGIBLE_RESOURCES`입니다. 업무 애플리케이션 생성·취약 실습 서비스 연결·실제 IP 차단은 수행하지 않았습니다. 이 결과는 플랫폼 설치 완료이며 기업 서비스 보호 인수 완료는 아닙니다.

HTTPS 경계 검사 9개가 통과했습니다. health, 로그인 필요 페이지, 세션·검토·승인·반려·차단·롤백 API의 미인증 거절, Cognito Authorization Code + PKCE와 Secure/HttpOnly cookie를 확인했습니다. 실제 관리자 초대·사람의 MFA 로그인·기업 Slack 수신·업무 WAF 차단/롤백은 회사 인수 항목입니다. 기본 관리자 이메일이나 Slack 계정은 연결하지 않습니다.

GitHub CI에서도 전체 소스 시험·CloudFormation 검사·배포 패키징·최종 공개 ZIP 검사가 통과했습니다. ZIP을 별도 경로로 추출한 독립 검사에서 아티팩트·소스·템플릿·Python SDK·Node 의존성 해시를 검증하고 설치 계획을 실행했습니다. 이 설치 계획 검사에서는 AWS·네트워크·Node/npm을 호출하지 않았습니다. 회사 설정과 원본 배포 결과는 공개 저장소와 배포 ZIP에 포함하지 않습니다.

새 회사 설치는 [빠른 설치](quickstart.md)의 Terraform 자동 연결 비활성 배포와 [운영 검증](operations.md)을 수행하고 결과를 외부 회사 디렉터리나 비공개 증거 저장소에 보관합니다. legacy의 `VALIDATED_AUTOMATIC_ONBOARDING_DISABLED`와 이에 해당하는 Terraform의 자동 연결 비활성 설정은 업무 서비스의 WAF 연결이나 운영 인수 완료를 뜻하지 않습니다.

운영 전에는 실제 발견 후보·공유 ACL 충돌·기존 규칙 보존, 회사 IAM writer 경계, 오리진 우회와 오탐, 관리자 MFA 로그인, HOTL/HITL Slack 요약·실제 결정 결과, 해당 서비스 IP의 실제 차단과 정확한 host CIDR 롤백을 확인합니다. 100건 합성 로그 시험은 최대 10,000건 입력의 처리 시간이나 실제 업무 부하 전체를 보장하지 않습니다. 자세한 한계와 인수 조건은 [보안 경계](security-boundaries.md)를 따릅니다.
