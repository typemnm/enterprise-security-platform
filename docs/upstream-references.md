# 참고 프로젝트와 설계 선택

이 문서는 공개 upstream을 검토한 설계 패턴과 이 제품의 차이를 기록합니다. 아래 프로젝트의 코드를 복사하지 않았고, fork·플러그인·런타임 dependency·호환 adapter로 포함하지 않습니다. 이 플랫폼은 자신의 설치·등록·사건·승인·대응 코드와 AWS 관리형 서비스로 동작합니다.

## Security Automations for AWS WAF

[AWS 공식 설명](https://docs.aws.amazon.com/solutions/latest/security-automations-for-aws-waf/solution-overview.html)은 기존 CloudFront/ALB 앞에 규칙을 배포하고 WAF로 요청을 검사하는 솔루션을 설명합니다. 참고한 것은 보호 입구의 범위를 명시하고, 선택 기능을 IaC로 구성하며, 로그 기반 탐지와 응답을 운영 가능한 모듈로 연결하는 방식입니다.

이 제품은 서비스가 미정인 회사 계정에서 태그·설치 범위로 대상을 발견합니다. 단일 공통 ACL을 모든 서비스에 자동 적용하지 않고 서비스 등록부·별도 IPSet·현재 연결을 검증합니다. 공유 ACL과 기존 로깅 충돌은 자동 덮어쓰기 대신 검토 상태로 중단합니다. HOTL/HITL 승인·실제 결과 저널·정확한 호스트 차단 롤백도 별도 구현합니다.

공식 문서는 해당 AWS 솔루션의 **2026년 12월 retirement 예정**과 이후 고객의 유지보수 책임을 안내합니다. 따라서 기존 솔루션 배포 코드에 런타임을 의존하지 않으며 WAFv2·관리형 규칙·현재 SDK 모델을 직접 검증합니다. retirement 일정은 위 공식 문서를 다시 확인합니다.

## Cloud Custodian

[cloud-custodian/cloud-custodian](https://github.com/cloud-custodian/cloud-custodian)과 [공식 AWS 시작 문서](https://cloudcustodian.io/docs/aws/gettingstarted.html)는 리소스에 대한 policy·filter·action·실행 모드와 dry run을 분리하는 규칙 엔진을 설명합니다. 이 제품에서는 대상 발견/선택, 서비스별 선언 정책, 계획/적용, 주기·이벤트 조정 및 구조화된 결과를 분리하는 패턴을 참고했습니다.

Cloud Custodian의 다중 클라우드·광범위 리소스/행동 DSL을 재구현하거나 포함하지 않습니다. 제품의 직접 자동 대응은 등록된 공개 ALB/CloudFront WAF HTTP 경로의 제한된 IP 차단과 관리자 롤백입니다. 광범위 terminate/delete·회사 전체 리소스 수정 행동을 사용자 policy에 허용하지 않습니다.

## Prowler

[prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)와 [공식 소개](https://docs.prowler.com/introduction)는 보안·준수 check와 findings·보고서·remediation 안내를 제공하는 플랫폼을 설명합니다. 이 제품에서는 검증 결과와 실제 조치 완료를 구분하고, 상태·증거·검토 사유를 보고하는 운영 패턴을 참고했습니다.

Prowler의 준수 framework/check 전체를 포함하거나 scan 결과를 자동 차단 승인으로 사용하지 않습니다. 회사는 Prowler 같은 독립 assessment를 별도 인수 과정에 사용할 수 있지만 해당 도구의 결과 수집·자동 remediation adapter는 이 패키지에 구현돼 있지 않습니다.

## 참고와 재사용의 구분

Cloud Custodian과 Prowler의 저장소는 Apache-2.0 라이선스를 표시합니다. 이 문서의 링크와 패턴 검토는 소스 복사나 외부 소프트웨어 배포를 의미하지 않습니다. 향후 코드·자산을 실제로 가져오는 변경은 출처·버전·라이선스·NOTICE를 별도로 기록하고 검토해야 합니다. 이 제품 자체의 라이선스는 저장소의 라이선스 파일을 따릅니다.

실제 연결·로그 전달·SDK·인증·실패 큐의 API 계약은 upstream 기능 이름이 아니라 현재 AWS 공식 문서, 잠긴 SDK 모델과 제품 테스트로 확인합니다. 회사 환경의 실제 권한·오탐·부하·Slack·차단/롤백 인수는 [운영](operations.md)과 [보안 경계](security-boundaries.md)를 따릅니다.
