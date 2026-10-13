/**
 * Automated Fault Detection System - History Module
 */

document.addEventListener('DOMContentLoaded', () => {
    // Quick keyboard shortcut for pagination
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') {
            return;
        }
        if (e.key === 'ArrowLeft') {
            const prev = document.querySelector('.pagination-links a:first-child');
            if (prev && prev.textContent.includes('Prev')) prev.click();
        } else if (e.key === 'ArrowRight') {
            const next = document.querySelector('.pagination-links a:last-child');
            if (next && next.textContent.includes('Next')) next.click();
        }
    });
});
