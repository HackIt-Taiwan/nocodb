import debug from 'debug';

export class NcDebug {
  private static logger: debug.Debugger;

  static initLogger(): debug.Debugger {
    if (!NcDebug.logger) {
      NcDebug.logger = debug('nc');
    }

    return NcDebug.logger;
  }

  static log(...args: any[]): void {
    if (!debug.enabled('nc')) {
      return;
    }

    const logger = NcDebug.initLogger();
    logger(...args);
  }
}
