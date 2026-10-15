# 검증 상태

공개 제품의 소스 시험, 배포 패키지의 무결성, 특정 회사 계정의 실제 운영 인수는 별도로 확인합니다. 이 문서에는 개인 계정·배포 URL·Slack 식별자를 포함하지 않습니다.

## v0.1.0 소스 검증

제품 소스 테스트 301개와 추가 공개·의존성 패키징 테스트 18개가 통과했습니다. Node 의존성은 깨끗한 npm 설치 직후 123개 패키지·6,250개 배포 파일의 해시를 기록하고, 시험 후·ZIP 생성·설치 시 추가·삭제·변조를 거절합니다. 이 결과는 로컬 시험이며 실제 기업 서비스의 공격 차단, Slack 수신, Cognito 로그인, 부하 처리 성공을 대신하지 않습니다.

사전 빌드 [v0.1.0 배포 패키지](https://github.com/typemnm/enterprise-security-platform/releases/tag/v0.1.0)는 SHA-256 파일로 외부 ZIP을 검증합니다. 패키지의 `build/release/manifest.json`에는 소스·템플릿·런타임·대시보드 해시와 `release_id`가 들어가며, `build/test-validation-result.json`의 `release_id`가 같은 릴리스인지 확인합니다. 설치 도구도 manifest에 기록된 파일 해시를 검사합니다.

## 실제 배포 검증

2026-10-15에 공개 제품 릴리스 `a7ab77f2a0f023bb886d918eb0bc359314387cb2a43a6f0afc01338415109aec`를 외부 계정 설정으로 실제 참조 환경에 적용했습니다. 서울 제어 영역·governance와 `us-east-1` 수집 영역의 CloudFormation 스택 3개가 완료됐고, 설치 도구가 배포 함수 코드 해시·Cognito MFA/관리자 전용 설정·HTTPS health를 확인했습니다.

일반 `--apply`로 자동 발견을 활성화했으며, `tagged`·`observe`·`dry_run=true`를 확인했습니다. 선택 태그가 붙은 지원 서비스는 0개여서 결과는 `DEPLOYED_NO_ELIGIBLE_RESOURCES`입니다. 업무 애플리케이션 생성·취약 실습 서비스 연결·실제 IP 차단은 수행하지 않았습니다. 이 결과는 플랫폼 설치 완료이며 기업 서비스 보호 인수 완료는 아닙니다.

HTTPS 경계 검사 9개가 통과했습니다. health, 로그인 필요 페이지, 세션·검토·승인·반려·차단·롤백 API의 미인증 거절, Cognito Authorization Code + PKCE와 Secure/HttpOnly cookie를 확인했습니다. 실제 관리자 초대·사람의 MFA 로그인·기업 Slack 수신·업무 WAF 차단/롤백은 회사 인수 항목입니다. 기본 관리자 이메일이나 Slack 계정은 연결하지 않습니다.

GitHub CI에서도 전체 소스 시험·CloudFormation 검사·배포 패키징·최종 공개 ZIP 검사가 통과했습니다. ZIP을 별도 경로로 추출한 독립 검사에서 아티팩트·소스·템플릿·Python SDK·Node 의존성 해시를 검증하고 설치 계획을 실행했습니다. 이 설치 계획 검사에서는 AWS·네트워크·Node/npm을 호출하지 않았습니다. 회사 설정과 원본 배포 결과는 공개 저장소와 배포 ZIP에 포함하지 않습니다.

회사는 [빠른 설치](quickstart.md)의 `--validation-only`와 [운영 검증](operations.md)을 수행하고 결과를 외부 회사 디렉터리나 비공개 증거 저장소에 보관합니다. `VALIDATED_AUTOMATIC_ONBOARDING_DISABLED`는 플랫폼 설치·연결 검증 상태이며, 업무 서비스의 WAF 연결이나 운영 인수 완료를 뜻하지 않습니다.

운영 전에는 실제 발견 후보·공유 ACL 충돌·기존 규칙 보존, 회사 IAM writer 경계, 오리진 우회와 오탐, 관리자 MFA 로그인, HOTL/HITL Slack 요약·실제 결정 결과, 해당 서비스 IP의 실제 차단과 정확한 host CIDR 롤백을 확인합니다. 100건 합성 로그 시험은 최대 10,000건 입력의 처리 시간이나 실제 업무 부하 전체를 보장하지 않습니다. 자세한 한계와 인수 조건은 [보안 경계](security-boundaries.md)를 따릅니다.
