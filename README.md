# Sigma rules

Detection rules I write and test as part of learning detection engineering, with the evidence for how each one was tested. Every rule here has been run against real log data, and each README entry says what was and wasn't verified.

## Rules

| Rule | Log source | ATT&CK | Status |
|---|---|---|---|
| [PsExec Service Installation](rules/windows/system/win_system_service_install_psexec.yml) | Windows System, Event ID 7045 | T1021.002, T1569.002 | Tested on generated events |
| [Suspicious Service Binary in Windows Directory (Possible Renamed PsExec)](rules/windows/system/win_system_service_install_suspicious_binary_windows_dir.yml) | Windows System, Event ID 7045 | T1021.002, T1569.002 | Tested on generated events |

The first rule matches the default PsExec service (`PSEXESVC`) by service name or binary path. The second is a heuristic for a renamed PsExec: PsExec copies its service binary into the Windows directory (through `ADMIN$`), so a demand-start, LocalSystem service whose binary sits directly in `C:\Windows` is unusual. It is noisier, which is why it is a separate rule at `medium` level.

## How the PsExec rules were tested

Chainsaw ran both rules against a Windows System log export containing three real 7045 events, generated with `sc.exe create`:

| Test service | Binary path | Default-name rule | Heuristic rule |
|---|---|---|---|
| PSEXESVC | C:\Windows\PSEXESVC.exe | match | match |
| testsvc | C:\Windows\testsvc.exe | no match | match |
| cleansvc | C:\Windows\System32\cleansvc.exe | no match | no match |

Results matched this table. `cleansvc` is the negative control: it has the same service type, start type and account as the others, and only the path differs, so the rules discriminate on the path and the name. I confirmed its event was present in the exported log (record 7576) and not just in the live log.

**A field-mapping gap.** The heuristic rule matches on `StartType`, which Chainsaw's stock mapping file `sigma-event-logs-all.yml` doesn't map (it has `ServiceStartType`, which is a different event's field name). With the stock mapping the rule silently matched nothing. Adding this entry to a copy of the mapping fixed it:

```yaml
      - from: StartType
        to: Event.EventData.StartType
```

The lesson: a Sigma rule only works if the backend maps its field names to the fields the log really contains.

**What I did not verify**

- Real PsExec traffic (`psexec -r` against a second machine). The events were created with `sc.exe`, which produces the same 7045 events but doesn't prove PsExec's events look identical.
- The Splunk conversion of these rules. An earlier combined version of the rule converted to a wrong query (the `OR` logic was flattened), which is why the rule is split in two. The CI below checks that both rules convert, but I haven't run the output in a Splunk instance.
- Any host other than a single Windows machine.
- False-positive rates in a real environment. The false-positive notes in each rule are reasoning, not measurements.

## Repeating the test

[`tests/Test-PsExecRules.ps1`](tests/Test-PsExecRules.ps1) automates the whole test on a Windows host (elevated PowerShell, ideally a VM): it creates the three services, exports the recent 7045 events, runs Chainsaw once per rule, compares the results with the expected table, and removes the services. Pass `-ShowRaw` to see Chainsaw's raw output.

```powershell
.\tests\Test-PsExecRules.ps1 -Chainsaw C:\tools\chainsaw\chainsaw.exe -Mapping C:\tools\chainsaw\mappings\sigma-event-logs-custom.yml
```

The script was written without being able to run Chainsaw where it was drafted, so if a result looks wrong, check the raw output first.

## Validation (CI)

On every push, GitHub Actions installs [sigma-cli](https://github.com/SigmaHQ/sigma-cli) and runs `sigma check` on the rules and converts them to Splunk, so a broken rule can't be merged. See [`.github/workflows/validate.yml`](.github/workflows/validate.yml).

## Layout

```
rules/windows/system/   rule files
tests/                  test script (generated artifacts go to tests/out, which is git-ignored)
.github/workflows/      CI validation
```
