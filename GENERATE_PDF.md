# Generate PDF - Quick Instructions

## Step 1: Ensure Server is Running

The local server should already be running at http://localhost:8000

If not, start it:
```bash
cd ~/data-integrations-guide
python3 -m http.server 8000
```

## Step 2: Open in Chrome/Edge

Open this URL in a Chromium-based browser:
```
http://localhost:8000
```

## Step 3: Print to PDF

1. Press **Cmd+P** (or File → Print)

2. In the Print dialog:
   - **Destination**: "Save as PDF"
   - **Layout**: Portrait
   - **Paper size**: A4 (styling from `docs/pdf.css` will apply)
   - **Margins**: Default
   - Click **"More settings"** and enable:
     - ✅ **Background graphics**
     - ✅ Headers and footers (optional - probably off)

3. Click **"Save"**

4. Save as:
   ```
   docs/data-integrations-modern-best-practices.pdf
   ```

## What's New in This PDF

✅ 16 new diagrams added
✅ Complete Stripe payment integration (~600 lines)
✅ All diagrams regenerated at 2400x1800 high resolution
✅ Much better readability and zoom quality

## Verify the PDF

After generating, check:
- All 44+ diagrams render correctly
- High-res diagrams are crisp and readable
- Code blocks wrap properly
- Page breaks are reasonable
- Stripe integration section is included (around page 50-60)

## File Size

The PDF will be larger due to high-res diagrams:
- Previous PDF: ~5-10 MB
- New PDF: ~15-25 MB (estimated)

This is expected and worth it for the improved quality.

## Alternative: Automated PDF Generation

If you want to automate this in the future, you can use Puppeteer:

```javascript
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto('http://localhost:8000', {
    waitUntil: 'networkidle0'
  });
  await page.pdf({
    path: 'docs/data-integrations-modern-best-practices.pdf',
    format: 'A4',
    printBackground: true,
    margin: {
      top: '16mm',
      right: '16mm',
      bottom: '16mm',
      left: '16mm'
    }
  });
  await browser.close();
})();
```

But for now, the manual browser method works perfectly fine!
