# PROCESS.md

## Milestone 1 — 프로젝트 초기화
- [x] `/home/yooseongc/packet-handler` 경로에 Rust 바이너리 프로젝트 초기화
- [x] 프로그램 이름을 `packet_handler`로 정리

## Milestone 2 — 명세/설계 문서 정비
- [x] `README.md`에 CLI 계약 반영
  - input 필수
  - output 미지정 시 cwd 기본 경로
  - `substitute_ip --from --to` 필수
  - `snaplen N` 필수
  - global option: `--ignore-checksum`, `--overwrite`
- [x] `DESIGN.md`를 README 명세와 동기화

## Milestone 3 — CLI/처리 파이프라인 구현
- [x] `clap` 기반 글로벌 옵션 + 서브커맨드 구현
- [x] 입력 파일 포맷 판별(`pcap`, `pcapng`)
- [x] 출력 경로 기본값(cwd) 계산 구현
- [x] overwrite 정책 구현

## Milestone 4 — 패킷 가공 기능 구현
- [x] `substitute_ip` 구현 (IPv4/IPv6 src/dst 치환)
- [x] 체크섬 처리 옵션 구현 (`--ignore-checksum`)
  - IPv4 header checksum
  - TCP/UDP checksum (IPv4/IPv6)
- [x] `snaplen N` 절단 구현

## Milestone 5 — pcap/pcapng 입출력 구현
- [x] pcap reader/writer 처리
- [x] pcapng reader/writer 처리
- [x] 패킷 단위 스트리밍 처리 루프 구성

## Milestone 6 — 빌드/테스트 자동화
- [x] Docker 기반 musl 빌드 `Dockerfile` 추가
- [x] `build.sh` 추가
  - runtime 이미지 빌드
  - exporter 이미지 빌드
  - `docker cp` 없이 `dist` 볼륨 마운트로 `./dist/packet_handler` 추출
- [x] `test.sh` 추가
  - `cargo check/test/build`
  - CLI 음수 테스트
  - `test/ndlp1.pcap` 실데이터 테스트
- [x] `TEST.md` 추가

## Milestone 7 — 실제 샘플 파일 검증
- [x] `test/ndlp1.pcap`로 `substitute_ip` 실행 검증
- [x] `test/ndlp1.pcap`로 `snaplen` 실행 검증

## Milestone 8 — 코드 리팩터링(계층 분리)
- [x] `src/main.rs`를 엔트리포인트만 남기고 슬림화
- [x] `src/cli.rs`로 CLI 계약 분리
- [x] `src/processor.rs`로 I/O 및 처리 파이프라인 분리
- [x] `src/transform.rs`로 패킷 변환 로직 분리
- [x] `cargo check` 및 `test.sh` 재실행 확인

## 다음 단계 (권장)
- [ ] 통합 테스트용 expected pcap 비교(fixture)
- [ ] 처리 통계 JSON 출력 옵션
- [ ] GitHub Actions(또는 CI)에서 `build.sh`/`test.sh` 자동 실행
