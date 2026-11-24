# CryptoTrace — 웹 암복호화 추출 → Burp 연동 도구

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 개요

**CryptoTrace**는 요청·응답을 클라이언트 JS로 암호화하는 웹을 진단할 때, 브라우저에서 **암복호화 알고리즘·키·IV·적용
위치를 자동 추출**하고 Burp Suite로 바로 넘겨 **평문으로 보고·변조·스캔**할 수 있게 하는 도구입니다. 크롬 확장
(DevTools 패널), 로컬 암복호화 서버(Node 또는 단일 실행 파일), Burp 확장(Montoya API, Java 17)으로 구성됩니다.
모든 처리는 진단자 PC 안에서만 이루어지며 외부 통신이 없습니다. 대상 서버로 새 요청을 만들어 보내지 않고,
진단자가 보내는 요청을 암호화만 합니다.

| 진단하며 겪은 문제 | 만든 기능 |
|---|---|
| 암호화된 요청·응답이라 Burp에서 내용을 볼 수 없음 | Burp **Decrypted** 탭에서 평문 확인·수정 |
| 알고리즘·키·IV·암호화 필드를 JS에서 손으로 찾아야 함 | 브라우저 후킹으로 자동 수집 → **Send to Burp** 한 번으로 적용·자가검증 |
| Repeater·Intruder·Scanner 페이로드가 암호문에 들어가 무의미 | 평문에 페이로드 → 전송 직전 자동 재암호화(서명·타임스탬프도 다시 계산) |

**안전 설계**
- **외부 통신 없음**: 크롬 확장 · 로컬 서버 · Burp 사이 통신은 모두 로컬에서만 이루어집니다. → [PRIVACY.md](PRIVACY.md)
- **브리지 보호**: Send to Burp는 `127.0.0.1`로만 보내고, Burp는 페어링 토큰·Host·확장 Origin이 모두 맞을 때만 받습니다.
  커스텀 JS가 든 설정은 Burp에서 확인한 뒤에만 로드합니다.
- **평문 유출 차단**: 암호화(또는 필수 서명 계산)에 실패한 요청은 평문으로 보내지 않고 막습니다.
- **페이지 코드 실행은 명시적으로**: 브라우저 오라클은 Burp **Options**와 패널 체크를 둘 다 켜야 동작하고, 대상 서버로는 아무것도 보내지 않습니다.
- **대상 데이터 분리**: 받은 설정은 `~/.cryptotrace/received/`, 내보낸 설정은 무시 폴더 `output/`에만 둡니다. 저장소에 올리지 않습니다.

> 허가받은 진단 범위 안에서만 사용하세요.

## 기능

| 구성 | 한 줄 설명 |
|---|---|
| **크롬 확장** (DevTools 패널) | WebCrypto(생성·파생·unwrap 키 포함)·CryptoJS·forge·JSEncrypt·sjcl·jsbn `RSAKey`·aes-js·Node `crypto` API(crypto-browserify) 호출을 후킹(Worker·iframe·webpack 번들 포함), 호출 위치로 Sources 이동 |
| **라이브러리 없는 암호화** | 모든 스크립트(Worker·eval 포함)에서 AES·SEED·ARIA·SM4·DES·SHA·MD5 상수를 찾아 위치 표시. 출처 모를 암호문은 만든 함수까지 역추적하고, **추적** 버튼으로 그 함수의 입력·출력·키 후보를 기록 → 서버가 알고리즘·키·IV를 자동 판정(AES·ARIA·SEED) |
| **브라우저 오라클** (ACTIVE, 기본 꺼짐) | 표준 알고리즘으로 판정되지 않는 커스텀·난독화 암호는 추적한 **원본 페이지 함수**를 Burp가 호출해 재암호화. 탭이 열려 있어야 하며 호출 간격 제한(기본 100ms) |
| **전송 위치 연결** | fetch/XHR·`Request`·sendBeacon 본문(JSON·form·FormData)·헤더·쿼리·쿠키에서 암호문 위치를 자동으로 찾음. hex/base64url로 다시 인코딩된 암호문, IV가 앞에 붙거나 별도 필드로 가는 경우도 인식. WebSocket은 패널 표시만 |
| **Send to Burp** | 캡처한 설정을 Burp로 바로 전송·로드·자가검증, 결과를 패널에 표시. 자동 전송 선택, 키를 잡지 못했거나 요청마다 바뀌는 키는 이유와 함께 빼고 보냄. **Export**로 손볼 초안 저장도 가능 |
| **로컬 서버** | AES·ARIA(CBC/CTR/GCM/ECB 등 OpenSSL 대칭 암호)·SEED(내장)·ChaCha20-Poly1305·RC4·RSA(OAEP/PKCS1, DER·PEM·JWK 키)·고정 키 ECDH, KDF(PBKDF2/scrypt/HKDF/OpenSSL EVP), 커스텀 JS 모듈, 로드 시 자가검증 |
| **적용 위치** | JSON 경로(`[*]`·`$..key` 포함)·본문 전체·헤더·쿼리·form·multipart·쿠키, 규칙별 경로 지정(`pathRegex`), base64/hex/base32/base58 및 중첩 인코딩. IV는 고정·암호문 앞붙임·별도 필드(JSON·헤더·쿼리·form, 재암호화 시 새 IV 기록) |
| **무결성 재계산** | 수정·재암호화 후 HMAC·해시·서명(RSA/ECDSA/EdDSA)·타임스탬프·nonce·커스텀 토큰 다시 계산. HMAC 입력 형식(어느 필드를 이어 붙였는지)은 캡처에서 자동 추론 |
| **세션 키** | 응답에서 새로 내려오는 키를 잡아 이후 요청·응답에 자동 반영 |
| **Burp — Decrypted 탭** | 요청·응답 평문 보기, 수정하면 자동 재암호화(HTTP/2 구조 유지). 공개키만 있어 복호화할 수 없는 필드는 `ct-keep:<암호문>`으로 표시 — 그대로 두면 원래 암호문 유지, 평문으로 바꾸면 암호화 |
| **Burp — 자동 암호화** | `X-CT-Plain: 1` 요청을 전송 직전 암호화, Scanner 평문 삽입 지점, Repeater/Intruder/Scanner 응답 복호화 |
| **Burp — Send to Repeater (Plain)** | 복호화된 요청을 평문 표식과 함께 Repeater로 전송 |

## 사용법

**요구 사항**: Chrome(또는 Chromium), Burp Suite Community/Professional, Java 17+.
Node.js 20+는 서버를 스크립트로 띄울 때만 필요합니다(`crypto-server.exe`를 쓰면 필요 없음).

1. **설치**: [Releases](https://github.com/9u4a/CryptoTrace/releases)에서 받습니다.
   - 크롬: `cryptotrace-chrome-<version>.zip` 압축 해제 → `chrome://extensions` → 개발자 모드 → **압축해제된 확장 프로그램 로드**
   - Burp: `cryptotrace-<version>-all.jar`를 **Extensions → Add → Java**로 로드
   - 서버: CryptoTrace 탭 **Server**에서 Launcher를 `crypto-server.exe`(Script 칸 비움) 또는 `node` + `server/src/main.mjs`로 지정
2. **처음 한 번 연결**: CryptoTrace 탭 상단 **Copy token** → DevTools **CryptoTrace** 패널 **Burp 설정**에 붙여 넣고 **Save & test**
3. **추출·적용**: 대상 페이지에서 **Hook ON** → 암호화가 일어나는 기능 사용 → **Send to Burp**.
   패널 아래에 `Burp: loaded · selftest n/n`이 뜨면 적용 완료입니다(자동 전송을 켜면 버튼도 필요 없음).
4. **진단**: Proxy 기록의 **Decrypted** 탭에서 평문 확인, 우클릭 **Send to Repeater (Plain)**으로 변조·재전송

- 파일로 옮기려면: 패널 **Export**(config.json) → 손으로 보완 → CryptoTrace 탭 **Configs → Add config...** → **Start / Reload**
- 연습용 대상: `node samples/server.mjs` → `http://127.0.0.1:8088` (직접 만든 샘플, 가짜 키)
- 지원 범위: [docs/COVERAGE.md](docs/COVERAGE.md) — 실제 사이트 패턴 33종을 자동 측정한 결과(되는 것·한계)
- 라이브러리 없는 암호화: 패널에 **unknown** 행이 생기면 선택 → **이 함수들 추적** → 같은 기능을 한 번 더 실행 → **Send to Burp**
- 판정 안 되는 커스텀 암호(`ct-keep:`으로만 보임): Burp **Options → ACTIVE: Browser oracle** + 패널 **Burp 설정 → 오라클(페이지 함수 실행)** 체크 → Decrypted 탭에서 `ct-keep:...`을 평문으로 바꿔 전송하면 페이지 함수가 암호화

## 변경 이력

버전별 변경사항과 빌드 산출물은 **[GitHub Releases](https://github.com/9u4a/CryptoTrace/releases)** 참고.
