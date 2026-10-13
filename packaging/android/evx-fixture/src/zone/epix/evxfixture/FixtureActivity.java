package zone.epix.evxfixture;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class FixtureActivity extends Activity {
    private FixtureHost fixture;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL);
        TextView status = new TextView(this);
        status.setText("Disposable fixed-game isolation fixture. EVX and native code loading are disabled.");
        Button button = new Button(this); button.setText("Run fixed game fixture once");
        fixture = new FixtureHost(this, text -> runOnUiThread(() -> status.append("\n" + text)));
        button.setOnClickListener(view -> {
            button.setEnabled(false);
            try { fixture.run(); } catch (Exception error) { status.append("\nRefused: " + error.getMessage()); }
        });
        layout.addView(status); layout.addView(button); setContentView(layout);
    }
    @Override public void onDestroy() { if (fixture != null) fixture.close(); super.onDestroy(); }
}
