# DESIGN.md

## 1. 아키텍처 개요

`packet_handler`는 단일 실행 파일 CLI이며 파이프라인은 아래와 같습니다.

1) CLI 인자/서브커맨드 검증
2) 입력 포맷 판별(pcap/pcapng)
3) 처리 경로 분기
   - transform(`substitute_ip`, `snaplen`)
   - filter(BPF)
   - analyze(conversation)
4) 결과 저장 또는 콘솔 출력

---

## 2. CLI 계약

### 글로벌 옵션
- `--input <PATH>`: 필수
- `--output <PATH>`: 선택(미지정 시 cwd 기본 출력)
- `--ignore-checksum`
- `--overwrite`

### 서브커맨드
1. `substitute_ip --map <FROM=TO> [--map ...]`
2. `snaplen <N>`
3. `filter <BPF_EXPR>`
4. `analyze [ether|ip|tcp|icmp|udp|arp]`

---

## 3. 모듈 계층

- `main.rs`: 엔트리포인트
- `cli.rs`: CLI 계약
- `processor.rs`: 처리 라우팅 및 파일 I/O
- `transform.rs`: 패킷 변환 로직

---

## 4. 핵심 처리 전략

### 4.1 substitute_ip (다중 매핑)
- `--map A=B` 리스트를 HashMap으로 파싱
- 패킷별 src/dst 치환
- 체크섬 보정은 `--ignore-checksum`에 따라 수행/생략

### 4.2 snaplen
- 모든 패킷 길이 `N`으로 truncate

### 4.3 filter (BPF)
- `tcpdump -r <in> -w <out> <bpf>` 사용
- 구문 오류 시 tcpdump non-zero -> 즉시 실패
- pcapng는 `tshark -F pcap`으로 변환 후 필터

### 4.4 analyze
- `tshark -q -z conv,<layer>` 기반 conversation 추출
- output 지정 없으면 stdout, 있으면 text 파일 저장

---

## 5. 빌드/배포

- Docker musl 빌드
- `build.sh`로 `./dist/packet_handler` 추출

---

## 6. 테스트

- `test.sh`
  - cargo check/test/build
  - CLI 음수 테스트
  - 샘플 파일 기반 처리 테스트

- 향후 강화
  - fixture 기반 expected 결과 비교
  - analyze/filter 회귀 테스트
