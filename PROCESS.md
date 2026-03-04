# PROCESS.md

## Milestone 1 — 프로젝트 초기화
- [x] `/home/yooseongc/packet-handler` 경로에 Rust 바이너리 프로젝트 초기화
- [x] 프로그램 이름을 `packet_handler`로 정리

## Milestone 2 — 명세/설계 문서 정비
- [x] `README.md`에 CLI 계약 반영
- [x] `DESIGN.md`를 README 명세와 동기화

## Milestone 3 — 기본 처리 기능
- [x] `clap` 기반 글로벌 옵션 + 서브커맨드 구현
- [x] pcap/pcapng 처리 루프 구현
- [x] `substitute_ip`(단일), `snaplen` 구현

## Milestone 4 — 빌드/테스트 자동화
- [x] Docker musl 빌드 `Dockerfile` 추가
- [x] `build.sh` 추가 (dist 볼륨 마운트 추출)
- [x] `test.sh`/`TEST.md` 추가

## Milestone 5 — 리팩터링
- [x] `src/main.rs` 엔트리포인트 슬림화
- [x] `src/cli.rs` / `src/processor.rs` / `src/transform.rs` 계층 분리

## Milestone 6 — 업그레이드 기능
- [x] `substitute_ip` 다중 매핑(`--map A=B` 반복)
- [x] `filter <BPF>` 추가
  - BPF 구문 오류 시 실패
  - pcapng 입력은 pcap 변환 후 필터
- [x] `analyze [ether|ip|tcp|icmp|udp|arp]` 추가
  - output 미지정 시 콘솔
  - output 지정 시 text 파일 저장
- [x] `analyze` 출력 가독성 개선
  - conversation 집계 후 정렬된 표 형식 출력

## 현재 상태
- [x] 코드/문서 동기화 완료
- [ ] 샘플 pcap 기반 filter/analyze 실데이터 회귀 추가 권장 (현재 `test/ndlp1.pcap` 파일 부재)
