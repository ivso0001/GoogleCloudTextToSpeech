package com.example.googlecloudtexttospeech;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;

public class MainActivity extends AppCompatActivity {
    private TextToSpeechHelper textToSpeechHelper;
    private EditText editText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textToSpeechHelper = new TextToSpeechHelper(this);

        editText = findViewById(R.id.editText);

        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                textToSpeechHelper.startConvert(editText.getText().toString());
            }
        });
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        textToSpeechHelper.destroy();
        textToSpeechHelper = null;
    }
}
