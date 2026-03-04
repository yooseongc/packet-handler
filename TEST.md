# TEST.md

## 테스트 목표

- `packet_handler` CLI 계약이 README 명세와 일치하는지 검증
- transform/filter/analyze 동작 검증
- Docker 기반 musl 빌드 가능성 검증

## 1) 로컬 테스트

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
  - 필수 인자 누락
  - `substitute_ip --map` 형식 오류
  - `filter` BPF 누락
- 샘플 파일(`test/ndlp1.pcap`)이 존재할 때 실데이터 테스트
  - 다중 매핑 substitute_ip
  - snaplen
  - filter(BPF)
  - analyze

## 2) Docker musl 빌드 테스트

```bash
cd /home/yooseongc/packet-handler
bash ./build.sh
```

기대 결과:
- runtime 이미지 빌드 성공
- exporter 이미지 빌드 성공
- `./dist/packet_handler` 바이너리 추출 성공

## 3) 수동 점검 체크리스트

- `substitute_ip --map A=B --map C=D` 다중 치환 정상
- `filter "tcp and port 443"` 구문 오류 시 실패
- pcapng 입력 filter 시 pcap 변환 후 결과 생성
- `analyze ip/tcp/udp/...` 출력이 콘솔/파일로 정상 분기
