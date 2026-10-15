# 보안 경계와 운영 인수

## 직접 지원하는 범위

공개 ALB와 활성 CloudFront의 WAFv2 HTTP 경로를 자동 연결합니다. ALB 뒤의 EC2·ECS·컨테이너는 이 입구의 보호 범위에 들어갑니다. 애플리케이션 취약점 수정, 직접 노출 오리진, IAM·DB·비 HTTP 트래픽까지 해결하지 않습니다. 오리진 우회 방지와 프록시의 실제 client IP 의미는 회사 서비스 인수에서 확인합니다.

NLB/TCP·RDS·S3·Lambda·직접 노출 EC2 및 API Gateway 직접 WAF 연결은 자동 부착 대상이 아닙니다. CloudTrail/GuardDuty 분석, 일반 포렌식 생성, Organizations 전체 계정 일괄 설치를 제공한다고 주장하지 않습니다. NACL 대응은 기본 비활성이며, 별도 검토한 서비스 정책·예약 슬롯·권한 없이는 사용하지 않습니다.

공유 ACL·Firewall Manager 소유·WAF Classic·기존 S3/Firehose 로그·subscription 충돌·namespace 충돌·권한이 불완전한 inventory는 변경 전에 `REVIEW_REQUIRED`로 중단합니다. 이 결과는 보호 완료나 자동 복구 완료가 아닙니다. 기존 정책의 선행 Allow·rule group이 IPSet 차단을 우회하는지도 실제 대응 전에 검토합니다.

## 기본 안전 모드

기본은 `tagged`, `observe`, `DefaultDryRun=true`, 관리형 WAF 규칙 Count입니다. 관찰 모드가 최초 WAF 연결을 금지하는 것은 아닙니다. 업무 변경 없이 플랫폼을 검증하려면 `--validation-only`를 사용합니다. 설치 모드를 변경하거나 태그를 해제해도 기존 WAF 연결과 차단 IP를 자동 삭제하지 않습니다.

실제 차단에는 서비스 enforce·설치 실행 허용·행동 허용·신선한 저장 증거·사건 범위·정책 revision이 모두 일치해야 합니다. HITL에는 관리자 결정과 callback commit도 필요합니다. 입력의 dry-run false, 성공 문자열, 임의 ARN, AI 추천이나 재해시한 proof가 실제 대응 권한을 만들지 않습니다.

## 저장 로그와 trusted writer

수집은 등록된 정확한 계정·리전·로그 그룹·stream·event ID·시각·본문 해시를 실제 저장 로그와 대조합니다. 저장 원본이 없는 수집 입력을 거절하고, 관측 저널이 없는 proof를 HOTL 자동 차단으로 승격하지 않습니다. 증거가 부족한 사건은 HITL 검토 또는 반려 경로로 처리합니다.

이 검증은 CloudWatch namespace 자체의 writer를 인증하는 AWS WAF 암호학적 서명이 아닙니다. 해당 namespace에 PutLogEvents를 할 수 있는 주체는 기록을 만들 수 있습니다. 등록부·사건·관측 counter·대응 작업의 writer와 배포 운영자도 신뢰 경계에 포함됩니다.

**enforce 전 필수 회사 IAM 인수:** 일반 업무 역할·사용자가 보안 WAF 로그 namespace를 쓰거나, 등록부·사건·counter를 변경하거나, 승인 함수를 직접 호출하지 못하도록 제한합니다. wildcard 로그 정책을 사용하는 업무 Lambda도 업무 로그 ARN만 허용하도록 좁히고 회사의 SCP/permission boundary 등으로 보안 제어 영역의 쓰기 범위를 제한합니다. 설치 도구는 미지의 회사 IAM/SCP를 임의로 변경하지 않습니다. 인수가 끝나기 전 observe를 유지합니다.

SDK용 `lambda:SourceFunctionArn` 조건과 backend 실패 전달·SQS poller 권한은 분리합니다. 같은 역할의 모든 Allow statement는 합쳐 평가되므로 한 statement의 조건만으로 역할 전체가 제한된다고 해석하지 않습니다. 실패 전달은 정확한 큐·키·서비스·계정 범위로 허용합니다.

## 신원과 데이터

Cognito의 서명·issuer·client/audience·expiry·token type, PKCE·state·nonce와 matching subject를 검증합니다. 관리자는 MFA를 등록하며 서비스별 읽기·관리 그룹을 확인합니다. 세션은 최대 15분이고 OAuth access/refresh token을 저장하지 않습니다. 비로그인 요청은 공개 health·로그인 흐름 외에 차단하며 상태 변경은 Origin·CSRF를 검증합니다.

승인 task token, 비공개 reasoning·본문·SFN 원본 입출력/Cause·Token은 public API·Slack·검증 결과에 내보내지 않습니다. 보고서와 원본 WAF 스냅샷은 회사의 비공개 KMS/S3·DynamoDB 접근 제어를 따릅니다. 스냅샷에 오리진 헤더 등 민감 설정이 들어갈 수 있으므로 회사 내부 접근도 제한합니다.

차단 롤백은 사건의 정확한 호스트 `/32` 또는 `/128`만 제거합니다. 넓은 CIDR 전체를 해제하거나 다른 서비스·임시 IPSet을 수정하지 않습니다. 관찰 모드로 돌아온 후에도 기존 차단의 관리자 정정은 허용하지만 새 차단 허용과는 구분합니다.

## 검증의 의미

로컬 테스트·템플릿 검사·플랫폼 설치·합성 관측·집계 전달 지표와 실제 회사 업무 인수를 분리합니다. 합성 CloudWatch 로그는 실제 WAF 공격 탐지 증거가 아니며, SNS 전달 지표는 특정 Slack 메시지 수신 증거가 아닙니다. 실제 관리자 최초 로그인·MFA, 회사 Slack 수신, 업무 WAF 차단·롤백·오탐·부하·오리진은 회사가 전용 시험 서비스로 확인합니다.
