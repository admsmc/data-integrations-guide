#!/usr/bin/env node

/**
 * Generate PDF from the data integrations guide
 * Requires: npm install puppeteer
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

async function generatePDF() {
  console.log('Launching browser...');
  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    
    // Set viewport for consistent rendering
    await page.setViewport({
      width: 1200,
      height: 1600,
      deviceScaleFactor: 2
    });

    console.log('Loading page from http://localhost:8000...');
    await page.goto('http://localhost:8000', {
      waitUntil: 'networkidle0',
      timeout: 60000
    });

    // Wait for Docsify to render content
    console.log('Waiting for content to render...');
    await page.waitForSelector('.markdown-section', { timeout: 30000 });
    
    // Additional wait to ensure all images and diagrams are loaded
    await page.evaluate(() => {
      return new Promise((resolve) => {
        const images = Array.from(document.images);
        let loadedCount = 0;
        
        if (images.length === 0) {
          resolve();
          return;
        }

        images.forEach((img) => {
          if (img.complete) {
            loadedCount++;
            if (loadedCount === images.length) resolve();
          } else {
            img.addEventListener('load', () => {
              loadedCount++;
              if (loadedCount === images.length) resolve();
            });
            img.addEventListener('error', () => {
              loadedCount++;
              if (loadedCount === images.length) resolve();
            });
          }
        });
      });
    });

    console.log('Generating PDF...');
    const pdfPath = path.join(__dirname, 'docs', 'data-integrations-modern-best-practices.pdf');
    
    await page.pdf({
      path: pdfPath,
      format: 'A4',
      margin: {
        top: '16mm',
        right: '16mm',
        bottom: '16mm',
        left: '16mm'
      },
      printBackground: true,
      preferCSSPageSize: true
    });

    console.log(`✓ PDF generated successfully: ${pdfPath}`);
    
    // Get file size
    const stats = fs.statSync(pdfPath);
    const fileSizeMB = (stats.size / (1024 * 1024)).toFixed(2);
    console.log(`  File size: ${fileSizeMB} MB`);

  } catch (error) {
    console.error('Error generating PDF:', error);
    throw error;
  } finally {
    await browser.close();
  }
}

// Main execution
(async () => {
  try {
    await generatePDF();
    process.exit(0);
  } catch (error) {
    console.error('Failed to generate PDF:', error.message);
    process.exit(1);
  }
})();
