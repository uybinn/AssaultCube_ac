# 2024 WHS AntiEngine팀 프로젝트 고도화

### 프로젝트명
- **Anti-Cheat 개발 고도화 프로젝트**

---

### 팀명
- **AntiEngine**

---

### 프로젝트 기간
- **2024.08.05 ~ 2024.09.13**

---

### 배경 및 동기
온라인 게임 산업이 성장함에 따라 다양한 형태의 부정 행위(치트, 핵 등)가 늘어나고 있습니다. 특히, 공격적인 해킹과 치트 프로그램은 게임의 공정성을 해치고 사용자 경험을 저해하는 큰 문제로 대두되고 있습니다. 기존의 사용자 모드에서 동작하는 안티치트 솔루션들은 종종 우회되거나 손쉽게 분석되어 효과가 떨어지는 경우가 많습니다. 이에 따라 게임 보안을 한층 강화하기 위해 커널 레벨에서 동작하는 안티치트 솔루션의 필요성이 대두되었습니다.

본 프로젝트의 동기는 기존 안티치트 시스템의 한계를 극복하고, 커널 모드에서 더욱 강력한 치트 방지 시스템을 구현하여, 공격자들이 직접 게임의 메모리나 중요한 시스템 자원에 접근하지 못하도록 하는 데 있습니다. 이를 통해 게임의 공정성을 보장하고 사용자 경험을 보호하는 것을 목표로 합니다.

---

### 목적
본 프로젝트는 커널 레벨에서 동작하는 안티치트 시스템을 고도화하여, 게임 내 부정 행위 탐지와 차단 성능을 극대화하는 것을 목표로 합니다. 특히, 기존에 구현된 안티치트 기능을 커널 모드로 확장하여, 더욱 강력하고 보안성이 높은 시스템을 개발하는 것이 핵심입니다. **AssaultCube(v1.3.0.2)**를 대상으로 커널 모드에서 DLL 인젝션 방지, 디버깅 탐지, PID 탐지와 같은 기능을 고도화하여 강력한 시스템을 구축하는 것이 최종 목표입니다.

---

### 개발 환경 및 도구
- **운영체제**: Windows 10 Pro 22H2
- **개발 도구**: Visual Studio 2022 Community, Windows 11 SDK 10.0.26100.0, WDK (Windows Driver Kit) 10.0.26100.1
- **테스트 및 디버깅 도구**: Cheat Engine, WinDbg, DbgView
- **테스트 핵**: [https://github.com/pathetic/assaultcube-internal](https://github.com/pathetic/assaultcube-internal)

---

### 프로젝트 세부 내용
1. **안티 디버깅 학습**
2. **커널 모드 연구**
3. **안티치트 기능 및 구현**
   - PID 탐지
   - Anti DLL Injection
   - Anti Debugging
4. **테스트 및 성능 검증**

---

### 결과물 및 기대효과
- **커널 모드 안티치트 시스템 구현**: 커널 레벨에서 동작하는 안티치트 드라이버(.sys 파일)를 개발하고, 이를 통해 게임에서 발생하는 부정 행위를 실시간으로 감지하고 차단합니다.

- **보안성 강화**: 커널 모드의 강력한 권한을 활용하여 치트 프로그램이 우회하기 어렵도록 구현, 게임 보안성을 대폭 강화합니다.

- **게임 공정성 및 사용자 신뢰성 향상**: 사용자 모드 기반의 기존 안티치트 시스템이 가졌던 한계를 극복하고, 더욱 신뢰할 수 있는 공정한 게임 환경을 제공합니다.

본 프로젝트는 안티치트 시스템의 새로운 기준을 제시하며, 고도화된 보안 기술을 통한 부정 행위 방지를 목표로 합니다.

---

### 동영상
- **테스트 영상 URL**: [https://youtu.be/9W3Vpx1WOhA](https://youtu.be/9W3Vpx1WOhA)
