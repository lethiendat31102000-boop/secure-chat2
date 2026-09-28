const CryptoJS = typeof window !== 'undefined' ? window.CryptoJS : (await import('crypto-js')).default;
if (!CryptoJS) throw new Error('Khong tai duoc CryptoJS. Hay chay npm install va npm start.');
export default CryptoJS;
