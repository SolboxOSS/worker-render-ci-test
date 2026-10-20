# Supply Chain / 공급망 관리

이 폴더는 「오픈소스 공급망 관리 가이드라인」(TTAK.KO-11.0246/R1 도메인 4)에 따른 이 저장소의 공급망 관리 기록이다.

| 파일 | 내용 |
|---|---|
| `asset-register.csv` | 통합자산목록 — 이 저장소가 사용하는 오픈소스 구성요소 (1구성요소 1행) |
| `exceptions.md` | 정책 예외(라이선스·취약점 위험 수용) 승인 기록. 릴리즈 CI의 취약점 게이트가 읽는다 |

## SBOM과 CI

| 워크플로 | 실행 시점 | 결과 |
|---|---|---|
| `supply-chain-pr.yml` | PR | 신규 의존성의 취약점·라이선스 점검 |
| `supply-chain-snapshot.yml` | main 변경, 매월 1일 | SBOM·보고서를 Actions 산출물로 보관 (관찰 모드) |
| `supply-chain-release.yml` | Release 게시 | SBOM(SPDX·CycloneDX)·NOTICE·고지패키지·체크섬을 **Release asset**으로 게시, attestation 생성 |

- 생성 도구: BomLens (https://github.com/sktelecom/bomlens), 버전은 워크플로의 `BOMLENS_VERSION`
- 생성 주체: Solbox Inc.
- 검증: `gh attestation verify <배포 tar.gz> --repo <owner>/<repo>`, `sha256sum -c SHA256SUMS`

## 문의

- 공급망 관리 담당: 솔박스 (Solbox) support@solbox.com
