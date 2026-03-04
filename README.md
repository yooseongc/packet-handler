# packet_handler

Rust 기반 CLI 프로그램으로, 입력받은 패킷 파일(`.pcap`, `.pcapng`)을 가공하여 저장합니다.

## 목표

- pcap / pcapng 파일 읽기
- IP 치환
- snaplen 절단
- 결과 저장

## CLI 스펙

### 공통 옵션 (Global Options)

- `--input <PATH>`: 원본 패킷 파일 경로 (**필수**, 없으면 에러)
- `--output <PATH>`: 결과 저장 경로 (옵션)
  - 지정하지 않으면 **프로그램 실행 현재 경로(cwd)** 기준으로 기본 출력 경로 사용
- `--ignore-checksum`: 체크섬 검증/보정을 무시
- `--overwrite`: 출력 파일이 이미 있어도 덮어쓰기 허용

### 서브커맨드

1. `substitute_ip`

```bash
packet_handler --input in.pcap substitute_ip --from 10.0.0.1 --to 192.168.0.1
```

- `--from <IP>`: 치환 대상 IP (**필수**)
- `--to <IP>`: 치환할 IP (**필수**)
- 두 인자 중 하나라도 없으면 에러

2. `snaplen`

```bash
packet_handler --input in.pcap snaplen 128
```

- `N`: 절단 길이(bytes) (**필수**)
- 인자가 없으면 에러

## 동작 규칙

1. 입력 파일 포맷
   - pcap, pcapng 지원

2. 출력 파일 포맷
   - 기본적으로 입력 포맷 유지

3. IP 치환
   - `substitute_ip` 실행 시 모든 패킷의 src/dst를 검사
   - `--from`과 일치하면 `--to`로 치환

4. snaplen 절단
   - `snaplen N` 실행 시 모든 패킷을 길이 `N`으로 절단

## 예시

```bash
# IP 치환
packet_handler \
  --input ./samples/in.pcapng \
  --output ./samples/out.pcapng \
  substitute_ip --from 10.10.10.5 --to 192.168.0.100

# snaplen 절단
packet_handler \
  --input ./samples/in.pcap \
  snaplen 128
```

## 에러 처리 정책

- `--input` 누락: 즉시 실패
- 입력 파일 없음/접근 불가: 즉시 실패
- 지원하지 않는 파일 포맷: 즉시 실패
- `substitute_ip`에서 `--from`, `--to` 누락: 즉시 실패
- `snaplen` 인자 누락 또는 비정상 값: 즉시 실패
- 출력 파일 이미 존재 + `--overwrite` 미지정: 실패

## 빌드

### Docker musl 빌드 목적

musl 빌드의 목적은 **정적 링크된 바이너리를 추출**해서 배포/이식성을 높이기 위함입니다.

### 실행

```bash
bash ./build.sh
```

빌드 후 산출물:
- `./dist/packet_handler`

참고:
- `docker cp`를 사용하지 않고, `dist` 볼륨 마운트(`-v ./dist:/dist`)로 바이너리를 추출합니다.

## 테스트

```bash
bash ./test.sh
```

- `test/ndlp1.pcap`가 있으면 실제 패킷 가공 테스트까지 수행합니다.

## 비기능 요구

- Rust stable에서 빌드
- Docker 기반 musl 정적 빌드 지원
- 대용량 파일 처리 시 스트리밍 방식(메모리 과다 사용 방지)
