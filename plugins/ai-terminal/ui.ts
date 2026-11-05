import 'mdui/mdui.css';
import 'mdui/components/button.js';
import 'mdui/components/checkbox.js';
import 'mdui/components/segmented-button.js';
import 'mdui/components/segmented-button-group.js';
import 'mdui/components/text-field.js';
import 'mdui/components/collapse.js';
import 'mdui/components/collapse-item.js';
import './styles.css';
import type { Button } from 'mdui/components/button.js';
import type { TextField } from 'mdui/components/text-field.js';

const consentForm = document.querySelector<HTMLFormElement>('.consent-form');
if (consentForm) {
  // MDUI validates the form, not the submitter's formnovalidate attribute.
  for (const button of consentForm.querySelectorAll<Button>('mdui-button[name="decision"]')) {
    button.addEventListener('click', () => {
      consentForm.noValidate = button.value === 'deny';
    }, { capture: true });
  }
  // MDUI's implicit text-field submit omits the decision button's name/value.
  consentForm.querySelector<TextField>('mdui-text-field[name="code"]')!.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    event.stopPropagation();
    consentForm.querySelector<Button>('mdui-button[value="approve"]')!.click();
  }, { capture: true });
}
