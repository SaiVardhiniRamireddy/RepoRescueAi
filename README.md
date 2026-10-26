# RepoRescue AI

RepoRescue AI is a hackathon MVP that scans a **public GitHub repository** for selected code patterns and uses Google's Gemma model (through the Google AI Studio API) to explain findings.

## Features

- Public GitHub repository URL input
- Limited source file scan using the GitHub REST API
- Lightweight static checks for selected risky patterns
- Gemma explanations and suggested next steps
- Severity metrics and expandable findings
- JSON report download
- Does not execute repository code

## Requirements

- Python 3.10 or newer
- Internet access
- Google AI Studio API key for the Gemma explanation feature (static scanning works without it)

## Run locally in Antigravity

1. Extract this project ZIP and open the `RepoRescueAI` folder in Antigravity.
2. Open the integrated terminal.
3. Create a virtual environment:

   **Windows PowerShell**
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use:
   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   .\.venv\Scripts\python.exe -m streamlit run app.py
   ```

   **macOS/Linux**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

5. Copy `.env.example` to `.env` and paste your Google AI Studio API key after `GOOGLE_API_KEY=`. Keep the key private. If you have no key yet, skip this step: repository scanning will still work, but Gemma explanations will be unavailable.
6. Start the app:
   ```bash
   streamlit run app.py
   ```
7. Open the local URL shown in the terminal, usually `http://localhost:8501`.
8. Enter a public repository URL and click **Scan repository**. Then click **Explain findings with Gemma** if the key is configured.

## Suggested demo

Use a small public Python repository containing one or two known patterns. Show:
1. The repository scan and file count.
2. Evidence for a pattern match.
3. Gemma's explanation and recommended next step.
4. Downloading the JSON report.

## Limitations

- This is a limited pattern-based scanner, not a complete security audit or general bug detector.
- A pattern match may be a false positive. No finding does not prove code is safe.
- Supports only public repositories and a limited set of file types, file sizes, and number of files.
- The scanner uses unauthenticated GitHub API requests; rate limits may apply.
- Gemma model availability depends on the API and account. If the default model is unavailable, set `GEMMA_MODEL` in `.env` to a Gemma model currently available to your Google AI Studio API key.
- Repository contents are external untrusted input. The app never executes downloaded code.
- Avoid scanning repositories whose contents you are not authorized to process.

## Deploying

For a fast demo, run locally first. To deploy on Streamlit Community Cloud, push the project to your own GitHub repository and configure `GOOGLE_API_KEY` (and optionally `GEMMA_MODEL`) in the app's Secrets settings. Never commit `.env` or an API key.
