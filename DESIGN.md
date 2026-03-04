# DESIGN.md

## 1. 아키텍처 개요

`packet_handler`는 단일 실행 파일 CLI로 동작하며, 처리 파이프라인은 아래와 같습니다.

1) CLI 인자/서브커맨드 검증
2) 입력 파일 로딩 스트림 시작
3) 패킷 단위 변환(`substitute_ip` 또는 `snaplen`)
4) 결과 파일 스트림 저장
5) 처리 통계 출력

---

## 2. CLI 계약 (README 동기화)

### 글로벌 옵션
- `--input <PATH>`: 필수, 없으면 에러
- `--output <PATH>`: 선택, 없으면 cwd 기준 기본 출력 경로 사용
- `--ignore-checksum`: 체크섬 검증/보정 생략
- `--overwrite`: 출력 파일 덮어쓰기 허용

### 서브커맨드
1. `substitute_ip --from <IP> --to <IP>`
   - `--from`, `--to` 둘 다 필수
   - 누락 시 즉시 실패

2. `snaplen <N>`
   - `N` 필수
   - 누락/비정상 값 시 즉시 실패

---

## 3. 모듈 분리 제안

### `cli`
- `clap` 기반 인자 파싱
- 글로벌 옵션 + 서브커맨드 검증

### `io`
- pcap/pcapng reader/writer 추상화
- 입력 포맷 판별 및 출력 포맷 유지

### `transform/substitute_ip`
- src/dst IP 치환
- 체크섬 재계산(옵션에 따라 생략)

### `transform/snaplen`
- 패킷 캡처 길이 절단
- 레코드 길이 필드 동기화

### `stats`
- 총 패킷 수
- IP 치환 수
- snaplen 절단 수

---

## 4. 데이터 처리 전략

- 대용량 대응을 위해 **패킷 단위 스트리밍 처리**
- 파일 전체 메모리 로드 금지
- 각 패킷 변환 후 즉시 출력 writer로 전달

---

## 5. IP 치환 상세

1. L2/L3 파싱 후 IPv4/IPv6 판별
2. `--from`과 일치하는 src/dst를 `--to`로 치환
3. `--ignore-checksum`이 false이면 체크섬/길이 필드 보정
   - IPv4 header checksum
   - TCP/UDP checksum(가능 시 pseudo-header 포함)

제약:
- IPv4↔IPv6 교차 치환 금지

---

## 6. snaplen 절단 상세

- 패킷 길이가 `N` 초과 시 `N`으로 truncate
- pcap/pcapng 레코드 length 메타 일관성 유지

---

## 7. 라이브러리 후보

- CLI: `clap`
- 에러: `anyhow`, `thiserror`
- 패킷/체크섬: `etherparse`
- pcap/pcapng: `pcap-file` 계열 검토

선정 기준:
- pcap + pcapng 동시 지원
- writer API 안정성

---

## 8. Docker + musl 빌드

멀티스테이지 Dockerfile:
1. Builder (Rust + musl target)
2. `x86_64-unknown-linux-musl` 릴리즈 빌드
3. 산출물만 최소 런타임/아티팩트로 분리

목표:
- 정적 링크 실행 파일
- 배포 의존성 최소화

---

## 9. 테스트 계획

### 단위 테스트
- `substitute_ip` 인자 검증/치환 함수
- `snaplen` 인자 검증/절단 함수

### 통합 테스트
- pcap/pcapng 입력 → 출력 검증
- 치환 수/절단 수 통계 검증
- `--overwrite`, `--ignore-checksum` 옵션 동작 검증

### 회귀 테스트
- 잘못된 입력 경로
- 비정상 포맷 파일
- edge snaplen(1, 큰 값)

---

## 10. 구현 단계

M1
- CLI 골격 + 글로벌 옵션/서브커맨드 검증

M2
- `substitute_ip` 구현 + 체크섬 정책

M3
- `snaplen` 구현 + pcapng 검증

M4
- Docker musl 빌드 + 통합 테스트/문서 보강
