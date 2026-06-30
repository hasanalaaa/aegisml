const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const publicDir = path.join(__dirname, 'public');

const svgBuffer = Buffer.from(`
<svg width="512" height="512" viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
  <rect width="512" height="512" fill="#05050C" />
  <path d="M256 64L100 130v150c0 100 60 170 156 220 96-50 156-120 156-220V130L256 64z" fill="#C9A84C" />
  <path d="M256 100v350c-70-40-120-100-120-180V150l120-50z" fill="#F0F0F8" opacity="0.8" />
</svg>
`);

async function generate() {
  await sharp(svgBuffer).resize(192, 192).toFile(path.join(publicDir, 'icon-192.png'));
  await sharp(svgBuffer).resize(512, 512).toFile(path.join(publicDir, 'icon-512.png'));
  
  // Screenshots
  await sharp({
    create: { width: 1280, height: 800, channels: 4, background: { r: 5, g: 5, b: 12, alpha: 1 } }
  }).composite([{ input: svgBuffer, gravity: 'center' }]).png().toFile(path.join(publicDir, 'screenshot-wide.png'));
  
  await sharp({
    create: { width: 390, height: 844, channels: 4, background: { r: 5, g: 5, b: 12, alpha: 1 } }
  }).composite([{ input: await sharp(svgBuffer).resize(200, 200).toBuffer(), gravity: 'center' }]).png().toFile(path.join(publicDir, 'screenshot-mobile.png'));
  
  console.log('Assets generated successfully!');
}

generate().catch(console.error);
