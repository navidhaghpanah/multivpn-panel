"""Issue certificates outside the HTTP worker; apply or roll back settings."""
import os
import sys

os.environ["IKEGUI_COLLECTOR"] = "0"
import app as panel


def main(domain):
    if not panel.DOMAIN_RE.fullmatch(domain):
        raise ValueError("Invalid domain")
    status = panel.DATA_DIR / "domain-status.json"
    panel.save_json(status, {"state": "running", "domain": domain})
    # Do not hold the global state lock during slow network issuance.
    before = panel.NGINX_SITE.read_text(encoding="utf-8")
    old_domain = panel.load_config().get("domain") or ""
    try:
        ok, note = panel.apply_domain_ssl(old_domain, domain)
        if not ok:
            raise RuntimeError(panel._public_flash_detail(note))
        with panel._lock:
            cfg = panel.load_config()
            cfg["domain"] = domain
            panel.save_config(cfg)
            panel.rewrite_ipsec_leftid(domain)
            panel.sync_accounts()
            panel.run(["ipsec", "reload"])
        panel.save_json(status, {"state": "complete", "domain": domain})
    except Exception as error:
        panel.NGINX_SITE.write_text(before, encoding="utf-8")
        panel.run(["systemctl", "reload", "nginx"])
        with panel._lock:
            cfg = panel.load_config()
            cfg["domain"] = old_domain
            panel.save_config(cfg)
            panel.rewrite_ipsec_leftid(old_domain)
            if old_domain:
                panel._copy_le_to_ipsec(old_domain)
                panel._write_certbot_hook(old_domain)
            panel.sync_accounts()
            panel.run(["ipsec", "reload"])
        panel.save_json(status, {"state": "failed", "domain": domain,
                                 "detail": panel._public_flash_detail(str(error))})
        raise


if __name__ == "__main__":
    main(sys.argv[1])
