# TEST.md

## 테스트 목표

- `packet_handler` CLI 계약이 README 명세와 일치하는지 검증
- pcap/pcapng 처리 코드가 빌드 가능한지 검증
- Docker 기반 musl 빌드 가능성 검증

## 1) 로컬 테스트

### 사전 조건
- Rust toolchain 설치
- `~/.cargo/bin/cargo` 사용 가능

### 실행

```bash
cd /home/yooseongc/packet-handler
bash ./test.sh
```

### 포함 항목
- `cargo check`
- `cargo test`
- debug 바이너리 빌드
- CLI 음수 테스트
  - 필수 인자 누락 시 실패 여부
  - 서브커맨드 필수 인자 누락 시 실패 여부

## 2) Docker musl 빌드 테스트

### 사전 조건
- Docker 설치

### 실행

```bash
cd /home/yooseongc/packet-handler
bash ./build.sh
```

### 기대 결과
- runtime 이미지 빌드 성공
- artifact target 빌드 성공
- musl 정적 바이너리 생성

## 3) 수동 기능 테스트 (권장)

샘플 pcap/pcapng 파일 준비 후 아래 시나리오 검증:

1. `substitute_ip` 정상 변환
2. `snaplen N` 정상 절단
3. `--ignore-checksum` 옵션 유무에 따른 처리 차이
4. `--overwrite` 옵션 유무에 따른 출력 파일 처리

## 4) 문제 발생 시 점검 포인트

- 입력 파일 경로 존재 여부
- 출력 경로 쓰기 권한
- pcap/pcapng 포맷 유효성
- Docker 빌드 시 네트워크/패키지 설치 실패 여부
