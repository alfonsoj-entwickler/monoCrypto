package systemcryptography.monocrypto;

/**
 * Data model for a single cipher entry in the main menu list.
 *
 * Each instance holds resource IDs (not raw strings/drawables) so the
 * Android resource system handles localization and density resolution.
 *
 * Fields:
 *   index  - unique cipher identifier passed to enter_Text_Activity via Intent extra
 *   icon   - drawable resource ID for the cipher's list icon
 *   element - string resource ID for the cipher name (list title)
 *   status  - string resource ID for the cipher short description (list subtitle)
 */
public class myMenuList {
    private int element;
    private int status;
    private int icon;
    private int index;

    /**
     * @param index   Unique cipher index (0–18), matched by the switch in enter_Text_Activity
     * @param i       Drawable resource ID for the cipher icon
     * @param n       String resource ID for the cipher name
     * @param s       String resource ID for the cipher subtitle / short description
     */
    public myMenuList(int index, int i, int n, int s) {
        this.index = index;
        this.icon = i;
        this.element = n;
        this.status = s;
    }

    public int getIndex() {
        return this.index;
    }

    public int getIcon() {
        return this.icon;
    }

    public int getElement() {
        return this.element;
    }

    public int getStatus() {
        return this.status;
    }
}
