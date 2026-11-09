# CryptoTrace — 웹 암복호화 추출 → Burp 연동 도구

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> **개발 중** — 첫 릴리스(0.1.0) 준비 중입니다. 아래는 0.1.0 범위입니다.

## 개요

**CryptoTrace**는 요청·응답을 클라이언트 JS로 암호화하는 웹을 진단할 때, 브라우저에서 **암복호화 알고리즘·키·IV·적용
위치를 자동 추출**하고 이를 Burp Suite에 연결해 **평문으로 보고·변조·스캔**할 수 있게 하는 도구입니다. 크롬 확장
(DevTools 패널), 로컬 암복호화 서버(Node), Burp 확장(Montoya API, Java 17)으로 구성됩니다. 모든 처리는 진단자
PC 안에서만 이루어지며 외부 통신이 없습니다. 대상 서버로 새 요청을 만들어 보내지 않고, 진단자가 보내는 요청을
암호화만 합니다.

| 진단하며 겪은 문제 | 만든 기능 |
|---|---|
| 암호화된 요청·응답이라 Burp에서 내용을 볼 수 없음 | Burp **Decrypted** 탭에서 평문 확인·수정 |
| 알고리즘·키·IV·암호화 필드를 JS에서 손으로 찾아야 함 | 브라우저 후킹으로 자동 수집 → 설정 파일 Export |
| Repeater·Intruder·Scanner 페이로드가 암호문에 들어가 무의미 | 평문에 페이로드 → 전송 직전 자동 재암호화 |

**안전 설계**
- **외부 통신 없음**: 크롬 확장 · 로컬 서버 · Burp 사이 통신은 모두 로컬에서만 이루어집니다. → [PRIVACY.md](PRIVACY.md)
- 암호화에 실패한 요청은 평문으로 보내지 않고 차단합니다.
- 추출한 키·설정은 대상 유래 데이터이므로 저장소에 올리지 않습니다(`output/`).

> 허가받은 진단 범위 안에서만 사용하세요.

## 기능

| 구성 | 한 줄 설명 |
|---|---|
| **크롬 확장** (DevTools 패널) | `crypto.subtle`·CryptoJS·forge·JSEncrypt·sjcl 호출과 fetch/XHR 전송 지점을 후킹(Worker·iframe 포함), 호출 위치로 Sources 이동, 설정 Export |
| **로컬 서버** | AES(CBC/GCM)·RSA 암복호화, 커스텀 JS 모듈, 설정 로드 시 자가검증(왕복 테스트) |
| **Burp — Decrypted 탭** | 요청·응답 평문 보기, 수정하면 자동 재암호화 |
| **Burp — 자동 암호화** | `X-CT-Plain: 1` 요청을 전송 직전 암호화, Scanner 평문 삽입 지점, 도구 응답 복호화 분석 |
| **Burp — Send to Repeater (Plain)** | 복호화된 요청을 평문 표식과 함께 Repeater로 전송 |

## 사용법

**요구 사항**: Chrome, Node.js 20+, Burp Suite Community/Professional, Java 17+

1. **크롬 확장 설치**: [Releases](https://github.com/9u4a/CryptoTrace/releases)의 `cryptotrace-chrome-<version>.zip` 압축 해제 →
   `chrome://extensions` → 개발자 모드 → **압축해제된 확장 프로그램 로드**
2. **추출**: 대상 페이지에서 DevTools → **CryptoTrace** 탭 → Hook ON → 기능 사용 → **Export**(config.json)
3. **Burp 확장 로드**: `cryptotrace-<version>-all.jar`를 **Extensions → Add → Java**로 로드 → 설정 탭에서 config 선택
4. **진단**: Proxy 기록의 **Decrypted** 탭에서 평문 확인, 우클릭 **Send to Repeater (Plain)**으로 변조·재전송

## 변경 이력

버전별 변경사항과 빌드 산출물은 **[GitHub Releases](https://github.com/9u4a/CryptoTrace/releases)** 참고.
