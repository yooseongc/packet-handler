# packet_handler

Rust 기반 CLI 프로그램으로, 입력받은 패킷 파일(`.pcap`, `.pcapng`)을 가공/필터/분석하여 저장하거나 출력합니다.

## 목표

- pcap / pcapng 파일 읽기
- IP 치환(다중 매핑)
- snaplen 절단
- BPF 필터 기반 추출
- conversation 분석 출력

## CLI 스펙

### 공통 옵션 (Global Options)

- `--input <PATH>`: 원본 패킷 파일 경로 (**필수**, 없으면 에러)
- `--output <PATH>`: 결과 저장 경로 (옵션)
  - 지정하지 않으면 **프로그램 실행 현재 경로(cwd)** 기준 기본 출력 경로 사용
- `--ignore-checksum`: 체크섬 검증/보정을 무시
- `--overwrite`: 출력 파일이 이미 있어도 덮어쓰기 허용

### 서브커맨드

1. `substitute_ip`

```bash
packet_handler --input in.pcap substitute_ip \
  --map 172.19.116.187=1.1.1.1 \
  --map 110.93.159.37=8.8.8.8
```

- `--map <FROM=TO>`: 1개 이상 필수
- 다중 매핑 동시 적용
- IPv4↔IPv6 교차 매핑은 에러

2. `snaplen`

```bash
packet_handler --input in.pcap snaplen 128
```

- `N`: 절단 길이(bytes) (**필수**)
- 인자가 없으면 에러

3. `filter`

```bash
packet_handler --input in.pcap filter "tcp and port 443"
```

- `BPF` 구문 필수
- BPF 구문 오류 시 즉시 실패
- pcapng 입력은 내부적으로 pcap 변환 후 필터 적용

4. `analyze [ether|ip|tcp|icmp|udp|arp]`

```bash
packet_handler --input in.pcap analyze ip
packet_handler --input in.pcap --output ./analysis.txt analyze tcp
```

- conversation 리스트를 가독성 높은 텍스트 표 형식으로 출력
- `analyze ip/tcp/udp/icmp/arp`는 `mac_flow(srcmac->dstmac)` 컬럼을 함께 표시
- `analyze ether`는 MAC 자체가 conversation이므로 `mac_flow` 컬럼을 표시하지 않음
- MAC이 중간에 바뀌면 서로 다른 conversation 행으로 모두 출력
- `analyze tcp`는 상태 요약(SYN/ACK/FIN/RST)과 재전송 건수를 함께 표시
- `analyze icmp`는 `icmp.type` 우선, 없으면 `icmpv6.type`을 사용
- `--output` 없으면 콘솔, 지정 시 text 파일 저장

## 동작 규칙

1. 입력 파일 포맷
   - pcap, pcapng 지원

2. 출력 파일 포맷
   - 기본적으로 입력 포맷 유지
   - filter의 pcapng 입력은 내부 변환 후 pcap 출력

3. 에러 처리 정책
- `--input` 누락: 즉시 실패
- 입력 파일 없음/접근 불가: 즉시 실패
- 지원하지 않는 파일 포맷: 즉시 실패
- `substitute_ip`에서 `--map` 누락/형식 오류: 즉시 실패
- `snaplen` 인자 누락 또는 비정상 값: 즉시 실패
- `filter` BPF 구문 오류: 즉시 실패
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
