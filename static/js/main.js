/**
 * CertVerify - Global JavaScript System
 * Handles UI interactions across all pages.
 */

document.addEventListener("DOMContentLoaded", () => {
  
  // ==========================================
  // 1. HOME PAGE: Typewriter Effect
  // ==========================================
  const typewriterElement = document.getElementById("typewriter");
  if (typewriterElement) {
    const words = ["Verify in seconds.", "Detect Photoshop forgery.", "Trust the math, not the paper."];
    let wordIndex = 0;
    let charIndex = 0;
    let isDeleting = false;

    function type() {
      const currentWord = words[wordIndex];
      
      if (isDeleting) {
        typewriterElement.textContent = currentWord.substring(0, charIndex - 1);
        charIndex--;
      } else {
        typewriterElement.textContent = currentWord.substring(0, charIndex + 1);
        charIndex++;
      }

      let typeSpeed = isDeleting ? 40 : 80;

      if (!isDeleting && charIndex === currentWord.length) {
        typeSpeed = 2000; // Pause at end of word
        isDeleting = true;
      } else if (isDeleting && charIndex === 0) {
        isDeleting = false;
        wordIndex = (wordIndex + 1) % words.length;
        typeSpeed = 500; // Pause before new word
      }

      setTimeout(type, typeSpeed);
    }
    setTimeout(type, 500); // Start typing
  }

  // ==========================================
  // 2. HOME PAGE: Animated Counters
  // ==========================================
  const counters = document.querySelectorAll('.counter');
  if (counters.length > 0) {
    const animateCounter = (counter) => {
      const target = +counter.getAttribute('data-target');
      const count = +counter.innerText;
      const inc = target / 100;

      if (count < target) {
        counter.innerText = Math.ceil(count + inc);
        setTimeout(() => animateCounter(counter), 20);
      } else {
        counter.innerText = target;
      }
    };

    const observer = new IntersectionObserver((entries, obs) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          obs.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });

    counters.forEach(counter => observer.observe(counter));
  }

  // ==========================================
  // 3. VERIFY PAGE: Drag & Drop Upload
  // ==========================================
  const dropZone = document.getElementById("dropZone");
  if (dropZone) {
    const fileInput = document.getElementById("fileInput");
    const submitBtn = document.getElementById("submitBtn");
    const previewContainer = document.getElementById("previewContainer");
    const fileNameDisplay = document.getElementById("fileName");
    const fileSizeDisplay = document.getElementById("fileSize");

    // Click to upload
    dropZone.addEventListener("click", () => fileInput.click());

    // Drag styling
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#10b981"; // Green
      dropZone.style.backgroundColor = "#ecfdf5";
    });

    dropZone.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#cbd5e1"; // Grey
      dropZone.style.backgroundColor = "#f8fafc";
    });

    // Handle Drop
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "#cbd5e1";
      dropZone.style.backgroundColor = "#f8fafc";
      
      if (e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        handleFileUpdate();
      }
    });

    // Handle selection
    fileInput.addEventListener("change", handleFileUpdate);

    function handleFileUpdate() {
      if (fileInput.files.length > 0) {
        const file = fileInput.files[0];
        fileNameDisplay.textContent = file.name;
        fileSizeDisplay.textContent = (file.size / 1024).toFixed(1) + " KB";
        
        previewContainer.classList.remove("d-none");
        dropZone.classList.add("d-none");
        submitBtn.disabled = false;
      }
    }

    // Reset function (attached to window so the HTML button can call it)
    window.resetUpload = function() {
      fileInput.value = "";
      previewContainer.classList.add("d-none");
      dropZone.classList.remove("d-none");
      submitBtn.disabled = true;
    };
  }

  // ==========================================
  // 4. RESULT PAGES: Copy to Clipboard
  // ==========================================
  const copyButtons = document.querySelectorAll('.copy-btn');
  copyButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const textToCopy = btn.getAttribute('data-copy');
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check text-success"></i> Copied!';
        setTimeout(() => {
          btn.innerHTML = originalHTML;
        }, 2000);
      });
    });
  });

});